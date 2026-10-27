// Package telegram is the approval channel of docs/05: it sends one-off and
// elevation prompts to the approver's private chat, long-polls the Bot API
// for button taps, checks each tap (docs/05 D4) and hands the ones that pass
// to the decision point through approval.Resolver.
//
// The package owns no approval or elevation state. Its tables map a prompt ID
// to the chat and message that show it, random callback keys to (prompt,
// action), and hold the getUpdates offset.
package telegram

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/audit"
)

// DefaultAPIURL is the Bot API base URL used when Config.APIURL is empty
// (docs/05 D10).
const DefaultAPIURL = "https://api.telegram.org"

// Defaults from docs/05 D2 and D11.
const (
	DefaultPollTimeout  = 50 * time.Second
	DefaultSendInterval = time.Second
	DefaultBackoffMin   = time.Second
	DefaultBackoffMax   = 30 * time.Second
)

// ErrStopped is returned by Run when the Bot API answered 409 Conflict or
// 401 Unauthorized. Polling does not resume until the process restarts:
// a 409 means someone else is taking the updates, and retrying would hand
// them the approvals (docs/05 D2, docs/gotchas.md).
var ErrStopped = errors.New("telegram: polling stopped")

// Config configures a Bot. Only TokenFile is required.
type Config struct {
	// APIURL is the Bot API base URL, DefaultAPIURL when empty.
	APIURL string
	// TokenFile holds the bot token. It is read on every API call so the
	// token can be rotated without a restart (docs/05 D10).
	TokenFile string
	// PollTimeout is the getUpdates long-poll timeout, DefaultPollTimeout
	// when zero. It is rounded up to whole seconds, at least one.
	PollTimeout time.Duration
	// SendInterval is the minimum gap between two messages to one chat,
	// DefaultSendInterval when zero; negative means no gap (tests).
	SendInterval time.Duration
	// BackoffMin and BackoffMax bound the retry delay after a failed
	// getUpdates, DefaultBackoffMin and DefaultBackoffMax when zero.
	BackoffMin time.Duration
	BackoffMax time.Duration
	// Now is the clock used for status lines without a time; time.Now
	// when nil.
	Now func() time.Time
	// Logger receives operational logs, slog.Default() when nil. Nothing
	// logged contains the token or a request URL.
	Logger *slog.Logger
	// HTTPClient is used for Bot API calls. Its redirect policy is
	// replaced: redirects are never followed.
	HTTPClient *http.Client
}

// Bot implements approval.Asker over the Telegram Bot API.
type Bot struct {
	cfg     Config
	apiURL  string
	db      *sql.DB
	audit   audit.Appender
	log     *slog.Logger
	http    *http.Client
	now     func() time.Time
	pollSec int

	resolver atomic.Pointer[resolverBox]
	running  atomic.Bool
	polling  atomic.Bool // deleteWebhook succeeded and the poller is live
	stopped  atomic.Bool // a 409 or 401 stopped polling for good

	queue sendQueue

	// /start replies run outside the poll loop (review L2): the loop only
	// enqueues, dropping when full or when the chat had a reply recently.
	startQ    chan int64
	startMu   sync.Mutex
	startLast map[int64]time.Time

	settleLocks keyedLocks

	// testHookBeforeTransition, if set, runs in Settle between reading a
	// prompt and its compare-and-set (tests only).
	testHookBeforeTransition func()
}

type resolverBox struct{ r approval.Resolver }

var _ approval.Asker = (*Bot)(nil)

// New checks cfg and returns a Bot. It reads the token file once so that a
// missing or malformed token is a startup error rather than a denied
// request. Call Migrate on db first.
func New(cfg Config, db *sql.DB, a audit.Appender) (*Bot, error) {
	if db == nil || a == nil {
		return nil, errors.New("telegram: database and audit appender are required")
	}
	if cfg.TokenFile == "" {
		return nil, errors.New("telegram: bot token file is not set")
	}
	if cfg.APIURL == "" {
		cfg.APIURL = DefaultAPIURL
	}
	u, err := url.Parse(cfg.APIURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, errors.New("telegram: api_url must be an http(s) URL without user info, query or fragment")
	}
	if cfg.PollTimeout <= 0 {
		cfg.PollTimeout = DefaultPollTimeout
	}
	pollSec := int((cfg.PollTimeout + time.Second - 1) / time.Second)
	if pollSec < 1 {
		pollSec = 1
	}
	if cfg.SendInterval == 0 {
		cfg.SendInterval = DefaultSendInterval
	}
	if cfg.SendInterval < 0 {
		cfg.SendInterval = 0
	}
	if cfg.BackoffMin <= 0 {
		cfg.BackoffMin = DefaultBackoffMin
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = DefaultBackoffMax
	}
	if cfg.BackoffMax < cfg.BackoffMin {
		cfg.BackoffMax = cfg.BackoffMin
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	var hc http.Client
	if cfg.HTTPClient != nil {
		hc = *cfg.HTTPClient
	}
	// A redirect would carry the token-bearing URL somewhere else, and its
	// error text would include that URL.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	b := &Bot{
		cfg:     cfg,
		apiURL:  trimSlash(cfg.APIURL),
		db:      db,
		audit:   a,
		log:     log.With("component", "telegram"),
		http:    &hc,
		now:     now,
		pollSec: pollSec,
	}
	b.queue.interval = cfg.SendInterval
	b.startQ = make(chan int64, startQueueLen)
	b.startLast = make(map[int64]time.Time)
	if _, err := b.readToken(); err != nil {
		return nil, err
	}
	return b, nil
}

// SetResolver sets where checked taps go. It must be called before Run;
// Run refuses to start without one.
func (b *Bot) SetResolver(r approval.Resolver) {
	if r == nil {
		b.resolver.Store(nil)
		return
	}
	b.resolver.Store(&resolverBox{r: r})
}

func (b *Bot) getResolver() approval.Resolver {
	if box := b.resolver.Load(); box != nil {
		return box.r
	}
	return nil
}

// Healthy reports whether the poller is running: deleteWebhook succeeded,
// Run has not returned, and no 409 or 401 stopped it (docs/05 D2). Before
// Run, prompts could be sent but no answer could arrive, so it is false.
func (b *Bot) Healthy() bool {
	return b.polling.Load() && !b.stopped.Load()
}

// Run deletes any webhook (keeping pending updates) and long-polls
// getUpdates until ctx ends or the Bot API answers 409 or 401, in which
// case it returns an error wrapping ErrStopped and Healthy stays false.
func (b *Bot) Run(ctx context.Context) error {
	if b.getResolver() == nil {
		return errors.New("telegram: Run called before SetResolver")
	}
	if !b.running.CompareAndSwap(false, true) {
		return errors.New("telegram: Run called twice")
	}
	defer b.polling.Store(false)

	if b.stopped.Load() {
		return ErrStopped
	}

	backoff := b.cfg.BackoffMin
	// docs/05 D2: getUpdates does not work while a webhook is set. Pending
	// updates are kept: they may be taps on prompts still open.
	for {
		err := b.call(ctx, "deleteWebhook", map[string]any{"drop_pending_updates": false}, nil, 0)
		if err == nil {
			break
		}
		if stop := b.fatal(err); stop != nil {
			return stop
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		b.log.Warn("deleteWebhook failed; retrying", "error", err.Error(), "backoff", backoff.String())
		if !sleepCtx(ctx, backoff) {
			return ctx.Err()
		}
		backoff = nextBackoff(backoff, b.cfg.BackoffMax)
	}

	offset, err := b.loadOffset(ctx)
	if err != nil {
		return fmt.Errorf("telegram: loading the update offset: %w", err)
	}
	go b.startReplier(ctx)
	b.polling.Store(true)
	b.log.Info("polling started")

	backoff = b.cfg.BackoffMin
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		updates, err := b.getUpdates(ctx, offset)
		if err != nil {
			if stop := b.fatal(err); stop != nil {
				return stop
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			b.log.Warn("getUpdates failed; backing off", "error", err.Error(), "backoff", backoff.String())
			if !sleepCtx(ctx, backoff) {
				return ctx.Err()
			}
			backoff = nextBackoff(backoff, b.cfg.BackoffMax)
			continue
		}
		backoff = b.cfg.BackoffMin
		for _, u := range updates {
			if u.id < offset {
				continue // already confirmed; a well-behaved API never sends these
			}
			b.handleUpdate(ctx, u)
			offset = u.id + 1
			// Persisted after each update (docs/05 D2). A failure here only
			// means redelivery after a restart, which the decision point's
			// compare-and-set makes harmless.
			if err := b.saveOffset(ctx, offset); err != nil && ctx.Err() == nil {
				b.log.Error("saving the update offset failed", "error", err.Error())
			}
		}
	}
}

// fatal marks the bot stopped and returns an error for a 409 or 401.
func (b *Bot) fatal(err error) error {
	var ae *apiError
	if errors.As(err, &ae) && (ae.Status == http.StatusConflict || ae.Status == http.StatusUnauthorized) {
		b.stopped.Store(true)
		b.polling.Store(false)
		b.log.Error("polling stopped for good: another poller or webhook uses the token, or the token was rejected",
			"method", ae.Method, "status", ae.Status)
		return fmt.Errorf("%w: %s answered %d", ErrStopped, ae.Method, ae.Status)
	}
	return nil
}

func nextBackoff(d, max time.Duration) time.Duration {
	d *= 2
	if d > max {
		return max
	}
	return d
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// sendQueue spaces messages to one chat at least interval apart (docs/05
// D11). Waiters for one chat are served one at a time; Go's mutex-like
// channel hand-off is close to, but not strictly, FIFO.
type sendQueue struct {
	interval time.Duration
	mu       sync.Mutex
	chats    map[int64]*chatSlot
}

type chatSlot struct {
	sem  chan struct{}
	last time.Time
}

// maxChatSlots bounds the per-chat send state; idle slots are dropped
// beyond it (a flood of /start from many accounts can't grow it forever).
const maxChatSlots = 1024

// pruneLocked drops slots that are idle and past their spacing interval.
// q.mu is held.
func (q *sendQueue) pruneLocked() {
	for id, s := range q.chats {
		select {
		case s.sem <- struct{}{}:
			if time.Since(s.last) > q.interval {
				delete(q.chats, id)
			}
			<-s.sem
		default: // in use
		}
	}
}

func (q *sendQueue) do(ctx context.Context, chatID int64, fn func() error) error {
	q.mu.Lock()
	if q.chats == nil {
		q.chats = make(map[int64]*chatSlot)
	}
	s, ok := q.chats[chatID]
	if !ok {
		if len(q.chats) >= maxChatSlots {
			q.pruneLocked()
		}
		s = &chatSlot{sem: make(chan struct{}, 1)}
		q.chats[chatID] = s
	}
	q.mu.Unlock()

	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.sem }()
	if !s.last.IsZero() {
		if wait := time.Until(s.last.Add(q.interval)); wait > 0 && !sleepCtx(ctx, wait) {
			return ctx.Err()
		}
	}
	err := fn()
	s.last = time.Now()
	return err
}
