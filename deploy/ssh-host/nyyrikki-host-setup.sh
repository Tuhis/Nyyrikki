#!/bin/sh
# Nyyrikki host setup: prepares a Linux host with OpenSSH >= 9.0 as an SSH
# target of Nyyrikki (docs/07-ssh-target.md, section 5.7; D3, D4, D7, D11,
# D15, D16), installs the trust pull and enrolls the host
# (docs/08-ssh-onboarding.md D5, D7, D13). The manual steps it automates are
# docs/setup/ssh-hosts.md.
#
# Nyyrikki serves this file at /hosts/<target>/setup.sh with data lines
# (NAME=value) and a terminator after the last line. The data lines are a
# quoted here-document that main reads as text and checks in full before
# it changes anything; they are never executed. main never returns: every
# path ends in exit, so nothing after the terminator runs.
#
#   sh setup.sh                 set the host up, or bring it up to date
#   sh setup.sh --enroll TOKEN  ... then enroll it (nyyrikkid enroll-token)
#   sh setup.sh --cacert FILE   ... and pull with FILE as Nyyrikki's TLS CA
#   sh setup.sh --reset-pull-state  ... even if a newer bundle was applied
#   sh setup.sh --dry-run       print every check and every file, change nothing
#   sh setup.sh --status        print what is installed, change nothing
#   sh setup.sh --uninstall     remove every Nyyrikki account, file and setting
#
# Rules this body keeps (docs/07 section 5.7): every error helper and trap
# handler ends in exit; die is never called in a pipeline, a command
# substitution or a subshell; the data lines are read with
# `while IFS= read -r line` on main's own stdin.

ny_init() {
	PATH=/usr/sbin:/usr/bin:/sbin:/bin
	export PATH
	LC_ALL=C
	export LC_ALL
	umask 022

	NY_DIR=/etc/ssh/nyyrikki
	NY_CA=$NY_DIR/user_ca.pub
	NY_KRL=$NY_DIR/revoked.krl
	NY_PRINC=$NY_DIR/principals
	NY_LIST=$NY_DIR/accounts
	NY_SSHD_DIR=/etc/ssh/sshd_config.d
	NY_SSHD=$NY_SSHD_DIR/50-nyyrikki.conf
	NY_SUDO_PREFIX=/etc/sudoers.d/50-nyyrikki-
	NY_LOGIND_DIR=/etc/systemd/logind.conf.d
	NY_LOGIND=$NY_LOGIND_DIR/50-nyyrikki.conf
	NY_SCOPE_DIR=/etc/systemd/system/session-.scope.d
	NY_SCOPE=$NY_SCOPE_DIR/50-nyyrikki.conf
	NY_SIGNERS=$NY_DIR/signers.pub
	NY_STATE=$NY_DIR/pull.state
	NY_PULL=$NY_DIR/pull.sh
	NY_PULLCONF=$NY_DIR/pull.conf
	NY_SERVERCA=$NY_DIR/server-ca.pem
	NY_HOSTKEY=/etc/ssh/ssh_host_ed25519_key
	NY_HOSTCERT=$NY_DIR/ssh_host_ed25519_key-cert.pub
	NY_CRON=/etc/cron.d/nyyrikki
	NY_PERIODIC=/etc/periodic/15min/nyyrikki-pull
	NY_LOCK=/run/nyyrikki-ssh.lock
	NY_NL='
'
	NY_WORK=
	NY_CHANGED=0
	NY_LOGIND_TOUCHED=0
	NY_DRY=0
	NY_UNINSTALL=0
	NY_SEQ=0
	NY_TARGET=
	NY_HUMANS=
	NY_ACCOUNTS=
	NY_CA_B64=
	NY_SOURCES=
	NY_SUDO=
	NY_COUNT=0
	NY_LISTED=
	NY_CREATE=
	NY_STALE=
	NY_STALE_EXISTING=
	NY_SSHD_BIN=
	NY_SYSTEMD=0
	NY_LOGIND_OURS=0
	NY_GSSAPI=0
	NY_SESSION_KILL=false
	NY_KUP=
	NY_KOU=
	NY_SIGNER_B64=
	NY_REVOKED_B64=
	NY_ISSUED=
	NY_URL=
	NY_STATUS=0
	NY_RESET=0
	NY_CACERT=
	NY_CACERT_SET=0
	NY_ENROLL=
	NY_ENROLL_SET=0
	NY_ENROLLING=0
	NY_CERT_ON=0
	NY_CERT_PENDING=0
	NY_CERT_PREV=0
	NY_LOCKED=0
	NY_SCHED=none
	NY_SCHED_WHY=
	NY_MARK=
	NY_MARK_AT=
	NY_MARK_BY=
	NY_NOW_S=
	NY_LIMIT_MS=
}

say() {
	printf '%s\n' "$*" 2>/dev/null || :
}

warn() {
	printf 'nyyrikki-host-setup: %s\n' "$*" >&2 2>/dev/null || :
}

# die stops the run. Before the first change it changes nothing; after it,
# it rolls back. Never call it in a pipeline, a $(...) or a subshell: the
# exit would end only that subshell.
die() {
	warn "$*"
	if [ "$NY_CHANGED" = 1 ]; then
		ny_rollback
	fi
	if [ "$NY_ENROLLING" = 1 ]; then
		ny_enroll_abort
	fi
	if [ "$NY_DRY" = 0 ] && [ "$NY_UNINSTALL" = 0 ] && [ "$NY_STATUS" = 0 ]; then
		warn "Nothing was changed. If an existing setup is in the way, merge it by hand: docs/setup/ssh-hosts.md."
	fi
	ny_cleanup
	exit 1
}

ny_cleanup() {
	if [ -n "$NY_WORK" ] && [ -d "$NY_WORK" ]; then
		rm -rf -- "$NY_WORK" 2>/dev/null || :
	fi
	# The lock (ny_lock) is released when this process exits, not here:
	# nothing may run between releasing it and the end.
	NY_LOCKED=0
}

# ny_lock takes the lock the trust pull takes too, so that the setup and a
# pull never change the trust files at once: a kernel lock (flock) on
# NY_LOCK, held on file descriptor 9 until this process exits. A holder
# that dies (a kill, a reboot) releases it, so there is nothing stale to
# take over. The file is root's, mode 0600, so no other user can open it
# to hold the lock. (A symbolic-link lock with a PID took over stale locks
# in steps no atomic operation tied together; two processes could both
# win. Review of #50.)
ny_lock() {
	command -v flock >/dev/null 2>&1 || die "refused: flock not found (util-linux, or BusyBox's flock)"
	[ ! -L "$NY_LOCK" ] || die "refused: $NY_LOCK is a symbolic link; remove it"
	# A failed redirection on exec would end the shell without a word:
	# try it in a subshell first.
	( umask 077 && : >>"$NY_LOCK" ) 2>/dev/null || die "refused: can't open the lock $NY_LOCK"
	ny_lk_umask=$(umask)
	umask 077
	exec 9>>"$NY_LOCK"
	umask "$ny_lk_umask"
	chown 0:0 -- "$NY_LOCK" && chmod 0600 -- "$NY_LOCK" || die "refused: can't secure the lock $NY_LOCK"
	flock -n 9 || die "refused: another Nyyrikki setup or trust pull is running; run this again when it has finished"
	NY_LOCKED=1
}

# shellcheck disable=SC2329 # called from trap
ny_on_signal() {
	trap '' INT TERM HUP PIPE
	warn "interrupted by SIG$1"
	if [ "$NY_CHANGED" = 1 ]; then
		ny_rollback
	fi
	if [ "$NY_ENROLLING" = 1 ]; then
		ny_enroll_abort
	fi
	ny_cleanup
	exit 1
}

# Runs on any exit that didn't come through die, a signal or the end of a
# successful run, such as the shell stopping on an expansion error.
# shellcheck disable=SC2329 # called from trap
ny_on_exit() {
	ny_status=$?
	trap '' INT TERM HUP PIPE
	if [ "$NY_CHANGED" = 1 ]; then
		warn "stopped unexpectedly"
		ny_rollback
	fi
	if [ "$NY_ENROLLING" = 1 ]; then
		warn "stopped unexpectedly"
		ny_enroll_abort
	fi
	ny_cleanup
	exit "$ny_status"
}

# --- checks on values ------------------------------------------------------

is_slug() {
	case $1 in
	'' | -* | *- | *[!a-z0-9-]*) return 1 ;;
	esac
	[ "${#1}" -le "$2" ]
}

# is_dec VALUE MAX: a decimal number without leading zeros, at most MAX.
is_dec() {
	case $1 in
	'' | *[!0-9]* | 0?*) return 1 ;;
	esac
	[ "${#1}" -le 3 ] && [ "$1" -le "$2" ]
}

is_cidr4() {
	ny_c4_a=${1%/*}
	ny_c4_m=${1#*/}
	[ "$ny_c4_a/$ny_c4_m" = "$1" ] || return 1
	is_dec "$ny_c4_m" 32 || return 1
	case $ny_c4_a in
	*[!0-9.]* | .* | *. | *..*) return 1 ;;
	esac
	ny_c4_ifs=$IFS
	IFS=.
	# shellcheck disable=SC2086 # split on dots; only digits and dots remain
	set -- $ny_c4_a
	IFS=$ny_c4_ifs
	[ "$#" = 4 ] || return 1
	for ny_c4_o in "$@"; do
		is_dec "$ny_c4_o" 255 || return 1
	done
	ny_c4_v=$((($1 << 24) | ($2 << 16) | ($3 << 8) | $4))
	if [ "$ny_c4_m" = 0 ]; then
		ny_c4_mask=0
	else
		ny_c4_mask=$(((0xFFFFFFFF << (32 - ny_c4_m)) & 0xFFFFFFFF))
	fi
	# Host bits must be zero: sshd refuses a from= entry with them set.
	[ $((ny_c4_v & ~ny_c4_mask & 0xFFFFFFFF)) = 0 ]
}

is_cidr6() {
	ny_c6_a=${1%/*}
	ny_c6_m=${1#*/}
	[ "$ny_c6_a/$ny_c6_m" = "$1" ] || return 1
	is_dec "$ny_c6_m" 128 || return 1
	case $ny_c6_a in
	'' | *[!0-9a-fA-F:]* | *:::* | :[!:]* | *[!:]:) return 1 ;;
	esac
	ny_c6_rest=${ny_c6_a#*::}
	ny_c6_dbl=0
	if [ "$ny_c6_rest" != "$ny_c6_a" ]; then
		ny_c6_dbl=1
		case $ny_c6_rest in
		*::*) return 1 ;;
		esac
	fi
	ny_c6_ifs=$IFS
	IFS=:
	# shellcheck disable=SC2086 # split on colons; only hex digits and colons remain
	set -- $ny_c6_a
	IFS=$ny_c6_ifs
	ny_c6_n=0
	for ny_c6_g in "$@"; do
		[ -z "$ny_c6_g" ] && continue
		[ "${#ny_c6_g}" -le 4 ] || return 1
		ny_c6_n=$((ny_c6_n + 1))
	done
	if [ "$ny_c6_dbl" = 1 ]; then
		[ "$ny_c6_n" -le 7 ]
	else
		[ "$ny_c6_n" = 8 ]
	fi
}

is_b64() {
	case $1 in
	'' | *[!A-Za-z0-9+/=]*) return 1 ;;
	esac
	return 0
}

# is_ms VALUE: Unix milliseconds as ISSUED carries them (docs/08 D4,
# D13): 13 digits without a leading zero, so the shell compares them
# exactly.
is_ms() {
	case $1 in
	[1-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) return 0 ;;
	esac
	return 1
}

# is_secs VALUE: Unix seconds, without a leading zero.
is_secs() {
	case $1 in
	'' | 0?* | *[!0-9]*) return 1 ;;
	esac
	[ "${#1}" -le 12 ]
}

# is_url VALUE: the URL data line (docs/08 D13): https, a host name or a
# bracketed IPv6 address, an optional port, nothing else. VALUE holds no
# line break (it is one data line), so grep sees it whole.
is_url() {
	[ "${#1}" -le 200 ] || return 1
	# grep -x matches per line: a value with a line break in it must not
	# pass on one good line (round 1 of #50).
	case $1 in *'
'*) return 1 ;; esac
	printf '%s\n' "$1" | grep -E -x -q 'https://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?'
}

# is_token VALUE: an enrollment token's form (docs/08 D6): nye1. and
# unpadded base64url.
is_token() {
	case $1 in
	nye1.?*) ;;
	*) return 1 ;;
	esac
	case ${1#nye1.} in
	*[!A-Za-z0-9_-]*) return 1 ;;
	esac
	[ "${#1}" -le 400 ]
}

# ed25519_b64 VALUE: VALUE's base64 if VALUE is "ssh-ed25519 <base64>",
# with nothing else; fails otherwise. Prints nothing on failure.
ed25519_b64() {
	case $1 in
	'ssh-ed25519 '*) ny_eb=${1#ssh-ed25519 } ;;
	*) return 1 ;;
	esac
	is_b64 "$ny_eb" || return 1
	printf '%s' "$ny_eb"
}

# has_word LIST WORD: WORD is one of the space-separated LIST.
has_word() {
	case " $1 " in
	*" $2 "*) return 0 ;;
	esac
	return 1
}

# --- reading the data lines --------------------------------------------------

# Reads the data lines from main's stdin. Every line is checked here; the
# loop runs in the main shell (no pipeline), so die stops the whole run.
ny_read_values() {
	ny_seen_end=0
	while IFS= read -r line; do
		if [ "$ny_seen_end" = 1 ]; then
			die "refused: a data line after END"
		fi
		case $line in
		[A-Z_]*=*) ;;
		*) die "refused: not a data line: $(ny_show "$line")" ;;
		esac
		ny_name=${line%%=*}
		ny_val=${line#*=}
		case $ny_name in
		*[!A-Z_]*) die "refused: not a data line: $(ny_show "$line")" ;;
		esac
		case $ny_name in
		TARGET)
			[ -z "$NY_TARGET" ] || die "refused: TARGET given twice"
			is_slug "$ny_val" 63 || die "refused: TARGET is not a target name: $(ny_show "$ny_val")"
			NY_TARGET=$ny_val
			;;
		HUMAN)
			is_slug "$ny_val" 29 || die "refused: HUMAN is not a human ID of at most 29 characters: $(ny_show "$ny_val")"
			has_word "$NY_HUMANS" "$ny_val" && die "refused: HUMAN $ny_val given twice"
			NY_HUMANS="${NY_HUMANS:+$NY_HUMANS }$ny_val"
			NY_ACCOUNTS="${NY_ACCOUNTS:+$NY_ACCOUNTS }ny-$ny_val"
			;;
		CA_KEY)
			case $ny_val in
			'ssh-ed25519 '*) ny_b64=${ny_val#ssh-ed25519 } ;;
			*) die "refused: CA_KEY is not an ssh-ed25519 key: $(ny_show "$ny_val")" ;;
			esac
			is_b64 "$ny_b64" || die "refused: CA_KEY holds characters other than base64: $(ny_show "$ny_val")"
			has_word "$NY_CA_B64" "$ny_b64" && die "refused: a CA_KEY given twice"
			NY_CA_B64="${NY_CA_B64:+$NY_CA_B64 }$ny_b64"
			;;
		SOURCE)
			is_cidr4 "$ny_val" || is_cidr6 "$ny_val" || die "refused: SOURCE is not an address range (CIDR): $(ny_show "$ny_val")"
			has_word "$NY_SOURCES" "$ny_val" && die "refused: SOURCE $ny_val given twice"
			NY_SOURCES="${NY_SOURCES:+$NY_SOURCES }$ny_val"
			;;
		SUDO)
			[ -z "$NY_SUDO" ] || die "refused: SUDO given twice"
			case $ny_val in
			true | false) NY_SUDO=$ny_val ;;
			*) die "refused: SUDO is neither true nor false: $(ny_show "$ny_val")" ;;
			esac
			;;
		SIGNER_KEY)
			ny_b64=$(ed25519_b64 "$ny_val") || die "refused: SIGNER_KEY is not an ssh-ed25519 key of base64 characters: $(ny_show "$ny_val")"
			has_word "$NY_SIGNER_B64" "$ny_b64" && die "refused: a SIGNER_KEY given twice"
			NY_SIGNER_B64="${NY_SIGNER_B64:+$NY_SIGNER_B64 }$ny_b64"
			;;
		REVOKED_CA_KEY)
			ny_b64=$(ed25519_b64 "$ny_val") || die "refused: REVOKED_CA_KEY is not an ssh-ed25519 key of base64 characters: $(ny_show "$ny_val")"
			has_word "$NY_REVOKED_B64" "$ny_b64" && die "refused: a REVOKED_CA_KEY given twice"
			NY_REVOKED_B64="${NY_REVOKED_B64:+$NY_REVOKED_B64 }$ny_b64"
			;;
		ISSUED)
			[ -z "$NY_ISSUED" ] || die "refused: ISSUED given twice"
			is_ms "$ny_val" || die "refused: ISSUED is not a time in Unix milliseconds: $(ny_show "$ny_val")"
			NY_ISSUED=$ny_val
			;;
		URL)
			[ -z "$NY_URL" ] || die "refused: URL given twice"
			is_url "$ny_val" || die "refused: URL is not an https URL of a host and port only: $(ny_show "$ny_val")"
			NY_URL=$ny_val
			;;
		END)
			[ "$ny_val" = "$NY_COUNT" ] || die "refused: END=$(ny_show "$ny_val") but $NY_COUNT value lines came before it: the file is cut off or changed"
			ny_seen_end=1
			continue
			;;
		*)
			die "refused: unknown data line name: $(ny_show "$ny_name")"
			;;
		esac
		NY_COUNT=$((NY_COUNT + 1))
	done
	[ "$ny_seen_end" = 1 ] || die "refused: no END line: the file is cut off"
	[ -n "$NY_TARGET" ] || die "refused: no TARGET line"
	[ -n "$NY_HUMANS" ] || die "refused: no HUMAN line"
	[ -n "$NY_CA_B64" ] || die "refused: no CA_KEY line"
	[ -n "$NY_SOURCES" ] || die "refused: no SOURCE line"
	[ -n "$NY_SUDO" ] || die "refused: no SUDO line"
	[ -n "$NY_SIGNER_B64" ] || die "refused: no SIGNER_KEY line"
	[ -n "$NY_ISSUED" ] || die "refused: no ISSUED line"
	[ -n "$NY_URL" ] || die "refused: no URL line"
	# docs/08 D4: the signers are trusted keys, and no trusted key is
	# revoked.
	for ny_k in $NY_SIGNER_B64; do
		has_word "$NY_CA_B64" "$ny_k" || die "refused: a SIGNER_KEY is not among the CA_KEYs"
	done
	for ny_k in $NY_REVOKED_B64; do
		has_word "$NY_CA_B64" "$ny_k" && die "refused: a REVOKED_CA_KEY is also a CA_KEY"
	done
	return 0
}

# ny_show VALUE: VALUE cut short and with anything but printable ASCII
# replaced, for error messages.
ny_show() {
	printf '%.80s' "$1" | tr -c ' -~' '?'
}

# --- the journal, for rolling back -------------------------------------------

# save_path PATH records the state of PATH before this run first changes
# it: a copy, or "absent". Called before every change.
save_path() {
	NY_CHANGED=1
	if grep -q -F -x -e "$1" "$NY_WORK/saved"; then
		return 0
	fi
	if [ -e "$1" ] || [ -L "$1" ]; then
		NY_SEQ=$((NY_SEQ + 1))
		cp -p -- "$1" "$NY_WORK/b$NY_SEQ" || return 1
		printf 'F b%s %s\n' "$NY_SEQ" "$1" >>"$NY_WORK/journal" || return 1
	else
		printf 'N - %s\n' "$1" >>"$NY_WORK/journal" || return 1
	fi
	printf '%s\n' "$1" >>"$NY_WORK/saved"
}

# forget_path PATH: never restore PATH on rollback. Used for what was taken
# away from an account this run then deleted.
forget_path() {
	awk -v p="$1" '$3 != p' "$NY_WORK/journal" >"$NY_WORK/journal.new" &&
		mv -f -- "$NY_WORK/journal.new" "$NY_WORK/journal"
}

# make_dir DIR: creates DIR (0755, root) if missing, recorded for rollback.
make_dir() {
	[ -d "$1" ] && return 0
	NY_CHANGED=1
	printf 'D - %s\n' "$1" >>"$NY_WORK/journal" || return 1
	mkdir -m 0755 -- "$1"
}

# put_file SRC DEST MODE installs SRC as DEST with MODE, owned by root,
# atomically. The temporary name starts with a dot, which sshd, sudo and
# logind all skip.
put_file() {
	save_path "$2" || return 1
	ny_pf_tmp=${2%/*}/.nyyrikki-new
	rm -f -- "$ny_pf_tmp" &&
		cp -- "$1" "$ny_pf_tmp" &&
		chown 0:0 "$ny_pf_tmp" &&
		chmod "$3" "$ny_pf_tmp" &&
		mv -f -- "$ny_pf_tmp" "$2"
}

remove_file() {
	if [ -e "$1" ] || [ -L "$1" ]; then
		save_path "$1" || return 1
		rm -f -- "$1"
	fi
}

ny_rollback() {
	trap '' INT TERM HUP PIPE
	trap - EXIT
	NY_CHANGED=0
	warn "rolling back this run's changes: every file returns to what it was before the run, including an earlier CA key or source address; only what step 2 took away stays away, since the target no longer grants it"
	ny_rb_krl=0
	ny_rb_dir=0
	if [ -f "$NY_WORK/journal" ]; then
		awk '{ l[NR] = $0 } END { for (i = NR; i > 0; i--) print l[i] }' \
			"$NY_WORK/journal" >"$NY_WORK/reverse" 2>/dev/null ||
			warn "rollback: can't read the journal in $NY_WORK"
		while IFS=' ' read -r ny_k ny_b ny_p; do
			case $ny_k in
			F)
				ny_tmp=${ny_p%/*}/.nyyrikki-new
				{ cp -p -- "$NY_WORK/$ny_b" "$ny_tmp" && mv -f -- "$ny_tmp" "$ny_p"; } ||
					warn "rollback: can't restore $ny_p (the old copy is $NY_WORK/$ny_b)"
				;;
			N)
				# A running sshd may read RevokedKeys from here until the
				# reload below, and refuses every key login without it.
				if [ "$ny_p" = "$NY_KRL" ]; then
					ny_rb_krl=1
				else
					rm -f -- "$ny_p" || warn "rollback: can't remove $ny_p"
				fi
				;;
			D)
				rm -f -- "$ny_p/.nyyrikki-new" 2>/dev/null
				if [ "$ny_p" = "$NY_DIR" ]; then
					ny_rb_dir=1
				else
					rmdir -- "$ny_p" || warn "rollback: can't remove $ny_p"
				fi
				;;
			A)
				if account_exists "$ny_p"; then
					pkill -KILL -u "$ny_p" >/dev/null 2>&1
					ny_delete_account "$ny_p" || warn "rollback: can't delete the account $ny_p"
				fi
				ny_rm_home "$ny_p" || warn "rollback: can't remove /home/$ny_p"
				;;
			esac
		done <"$NY_WORK/reverse"
	fi
	if [ "$NY_LOGIND_TOUCHED" = 1 ] && [ "$NY_SYSTEMD" = 1 ]; then
		systemctl daemon-reload || warn "rollback: systemctl daemon-reload failed"
		ny_restart_logind || warn "rollback: restarting systemd-logind failed"
	fi
	ny_rb_reloaded=0
	if "$NY_SSHD_BIN" -t; then
		if ny_reload_sshd; then
			ny_rb_reloaded=1
		else
			warn "rollback: reloading sshd failed"
		fi
	else
		warn "rollback: sshd -t fails on the restored configuration; sshd was not reloaded"
	fi
	if [ "$ny_rb_reloaded" = 1 ]; then
		[ "$ny_rb_krl" = 1 ] && { rm -f -- "$NY_KRL" || warn "rollback: can't remove $NY_KRL"; }
		[ "$ny_rb_dir" = 1 ] && { rmdir -- "$NY_DIR" || warn "rollback: can't remove $NY_DIR"; }
	elif [ "$ny_rb_krl" = 1 ] || [ "$ny_rb_dir" = 1 ]; then
		warn "rollback: kept $NY_KRL, which the running sshd may still read; remove $NY_DIR once sshd is reloaded"
	fi
	warn "rolled back"
	ny_cleanup
	exit 1
}

# --- host facts ---
#
# POSIX sh has no local variables: each helper below that a loop calls uses
# names of its own (ny_<initials>_...), so it can't change its caller's.------------------------------------------------------------

ny_reload_sshd() {
	if [ "$NY_SYSTEMD" = 1 ]; then
		for ny_rs_u in ssh.service sshd.service; do
			if systemctl is-active --quiet "$ny_rs_u"; then
				systemctl reload "$ny_rs_u" || return 1
			fi
		done
		return 0
	fi
	for ny_rs_pf in /run/sshd.pid /var/run/sshd.pid; do
		if [ -s "$ny_rs_pf" ]; then
			IFS= read -r ny_rs_pid <"$ny_rs_pf" || return 1
			case $ny_rs_pid in
			'' | *[!0-9]*) return 1 ;;
			esac
			kill -HUP "$ny_rs_pid" || return 1
			return 0
		fi
	done
	# No sshd running: it reads the new configuration when it starts.
	return 0
}

# ny_rm_home NAME removes /home/NAME, only for a Nyyrikki account name.
ny_rm_home() {
	case $1 in
	ny-?*) is_slug "${1#ny-}" 29 || return 1 ;;
	*) return 1 ;;
	esac
	# shellcheck disable=SC2115 # $1 is checked above
	rm -rf -- "/home/$1"
}

# ny_delete_account NAME deletes a Nyyrikki account, its home and the
# mail spool useradd may have made for it (RHEL-family hosts do).
ny_delete_account() {
	ny_da_uid=$(id -u -- "$1") || return 1
	userdel -- "$1" || return 1
	ny_rm_home "$1" || return 1
	for ny_da_m in "/var/mail/$1" "/var/spool/mail/$1"; do
		if [ -f "$ny_da_m" ] && [ ! -L "$ny_da_m" ] && [ "$(stat -c %u -- "$ny_da_m")" = "$ny_da_uid" ]; then
			rm -f -- "$ny_da_m" || return 1
		fi
	done
	return 0
}

# account_exists NAME
account_exists() {
	getent passwd "$1" >/dev/null 2>&1
}

# account_check NAME: prints why NAME isn't as the setup created it, or
# nothing. Returns non-zero if it isn't.
account_check() {
	ny_pw=$(getent passwd "$1") || {
		printf 'is not in the passwd database'
		return 1
	}
	ny_sh=${ny_pw##*:}
	ny_rest=${ny_pw%:*}
	ny_home=${ny_rest##*:}
	ny_uid=$(printf '%s' "$ny_pw" | cut -d: -f3)
	ny_shadow=$(getent shadow "$1" | cut -d: -f2)
	if [ "$ny_shadow" != '*' ]; then
		printf "its password field isn't '*'"
		return 1
	fi
	if [ "$ny_sh" != /bin/sh ]; then
		printf "its shell is %s, not /bin/sh" "$ny_sh"
		return 1
	fi
	if [ "$ny_home" != "/home/$1" ]; then
		printf "its home is %s, not /home/%s" "$ny_home" "$1"
		return 1
	fi
	if [ ! -d "$ny_home" ] || [ -L "$ny_home" ] || [ "$(stat -c %u -- "$ny_home")" != "$ny_uid" ]; then
		printf "its home %s isn't a directory it owns" "$ny_home"
		return 1
	fi
	# Root by another way than Nyyrikki's own sudoers file for it, e.g.
	# given by an approved command earlier: a re-run with SUDO=false would
	# otherwise leave it. Best effort: an account that had root can keep it
	# in ways no check finds (docs/setup/ssh-hosts.md).
	if [ "$ny_uid" = 0 ]; then
		printf 'its UID is 0'
		return 1
	fi
	ny_ac_gs=$(id -Gn -- "$1" 2>/dev/null) || {
		printf "can't list its groups"
		return 1
	}
	ny_ac_names="$1 #$ny_uid"
	for ny_ac_gid in $(id -G -- "$1" 2>/dev/null); do
		ny_ac_names="$ny_ac_names %#$ny_ac_gid"
	done
	for ny_ac_g in $ny_ac_gs; do
		case $ny_ac_g in
		root | sudo | wheel | admin | docker | lxd | incus | disk)
			printf 'it is in the group %s' "$ny_ac_g"
			return 1
			;;
		esac
		ny_ac_names="$ny_ac_names %$ny_ac_g"
	done
	for ny_ac_f in /etc/sudoers /etc/sudoers.d/*; do
		[ -f "$ny_ac_f" ] || continue
		# Only the setup's own file for this account: step 2 or step 6
		# handles it. Any other file, even one named like the setup's, counts.
		case $ny_ac_f in
		"$NY_SUDO_PREFIX$1" | */.nyyrikki-new) continue ;;
		esac
		# Comment lines aside: "#" then a digit is a UID, not a comment.
		ny_ac_rules=$(grep -E -v -- '^[[:space:]]*#([^0-9]|$)' "$ny_ac_f")
		case $? in
		0 | 1) ;; # 1: nothing but comments
		*)
			printf "can't read %s" "$ny_ac_f"
			return 1
			;;
		esac
		if printf '%s\n' "$ny_ac_rules" | grep -E -q -- '^[[:space:]]*ALL[[:space:]]'; then
			printf '%s gives every user a rule (ALL)' "$ny_ac_f"
			return 1
		fi
		for ny_ac_n in $ny_ac_names; do
			if printf '%s\n' "$ny_ac_rules" | grep -E -q -- "(^|[^A-Za-z0-9_.-])$ny_ac_n([^A-Za-z0-9_.-]|\$)"; then
				printf '%s names %s' "$ny_ac_f" "$ny_ac_n"
				return 1
			fi
		done
	done
	return 0
}

# ny_restart_logind restarts logind, clearing the start rate limit first:
# re-runs and rollbacks in quick succession would otherwise hit it.
ny_restart_logind() {
	systemctl reset-failed systemd-logind.service >/dev/null 2>&1
	systemctl restart systemd-logind.service
}

# ny_end_hint NAME: how to end NAME's processes, for messages. A user
# manager can outlive the account's sessions when logind restarts during
# its stop delay; loginctl then doesn't know the user.
ny_end_hint() {
	if [ -d /run/systemd/system ]; then
		printf 'loginctl terminate-user %s, or systemctl stop user@%s.service' "$1" "$(id -u -- "$1" 2>/dev/null)"
	else
		printf 'pkill -u %s' "$1"
	fi
}

# has_processes NAME: 0 if NAME has processes, 1 if not; anything else
# is an error.
has_processes() {
	pgrep -u "$1" >/dev/null 2>&1
}

# ny_pam_reaches_systemd: pam_systemd is reached from the session lines of
# /etc/pam.d/sshd, following @include, include and substack.
ny_pam_reaches_systemd() {
	ny_queue=sshd
	ny_done=
	ny_depth=0
	while [ -n "$ny_queue" ] && [ "$ny_depth" -lt 20 ]; do
		ny_depth=$((ny_depth + 1))
		ny_f=${ny_queue%% *}
		if [ "$ny_f" = "$ny_queue" ]; then ny_queue=; else ny_queue=${ny_queue#* }; fi
		has_word "$ny_done" "$ny_f" && continue
		ny_done="$ny_done $ny_f"
		[ -f "/etc/pam.d/$ny_f" ] || continue
		ny_res=$(awk '
			{ sub(/#.*/, "") }
			$1 == "@include" { print "I " $2; next }
			{
				t = $1; sub(/^-/, "", t)
				if (t != "session") next
				i = 2
				if ($i ~ /^\[/) { while (i <= NF && $i !~ /\]$/) i++ }
				c = $i; m = $(i + 1)
				if (c == "include" || c == "substack") { print "I " m; next }
				n = m; sub(/.*\//, "", n)
				if (n == "pam_systemd.so") print "Y"
			}' "/etc/pam.d/$ny_f") || return 1
		case "$NY_NL$ny_res$NY_NL" in
		*"${NY_NL}Y$NY_NL"*) return 0 ;;
		esac
		for ny_i in $(printf '%s\n' "$ny_res" | sed -n 's/^I //p'); do
			case $ny_i in
			*/* | '' | .*) continue ;;
			esac
			ny_queue="${ny_queue:+$ny_queue }$ny_i"
		done
	done
	return 1
}

# ny_logind_values: sets NY_KUP (yes/no) and NY_KOU (space-separated) to
# logind's effective KillUserProcesses and KillOnlyUsers.
ny_logind_values() {
	ny_lv_b=$(busctl get-property org.freedesktop.login1 /org/freedesktop/login1 \
		org.freedesktop.login1.Manager KillUserProcesses 2>/dev/null) || return 1
	case $ny_lv_b in
	'b true') NY_KUP=yes ;;
	'b false') NY_KUP=no ;;
	*) return 1 ;;
	esac
	ny_lv_b=$(busctl get-property org.freedesktop.login1 /org/freedesktop/login1 \
		org.freedesktop.login1.Manager KillOnlyUsers 2>/dev/null) || return 1
	case $ny_lv_b in
	'as '*) ;;
	*) return 1 ;;
	esac
	NY_KOU=$(printf '%s\n' "$ny_lv_b" | awk '{ for (i = 3; i <= NF; i++) { gsub(/"/, "", $i); printf "%s%s", (i > 3 ? " " : ""), $i } }') || return 1
}

# ny_distro_measured: the distribution is one where docs/07 M18 (session
# kill through logind, root processes under sudo included) was measured.
ny_distro_measured() {
	[ -r /etc/os-release ] || return 1
	ny_id=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')
	ny_ver=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '"')
	case $ny_id in
	debian)
		case $ny_ver in
		'' | *[!0-9]*) return 1 ;;
		esac
		[ "$ny_ver" -ge 13 ]
		;;
	*) return 1 ;;
	esac
}

# ny_config_files: sshd's main configuration, its drop-ins other than
# Nyyrikki's, and the files they include, one per line.
ny_config_files() {
	ny_list=/etc/ssh/sshd_config
	for ny_c in "$NY_SSHD_DIR"/*.conf; do
		[ -e "$ny_c" ] || continue
		[ "$ny_c" = "$NY_SSHD" ] && continue
		ny_list="$ny_list$NY_NL$ny_c"
	done
	ny_inc=$(printf '%s\n' "$ny_list" | while IFS= read -r ny_c; do
		awk '{ sub(/#.*/, ""); n = split($0, w, /[ \t=]+/); s = 1; if (w[1] == "") s = 2
			if (tolower(w[s]) == "include") for (i = s + 1; i <= n; i++) if (w[i] != "") print w[i] }' "$ny_c"
	done)
	printf '%s\n' "$ny_list"
	ny_globs=
	set -f
	for ny_g in $ny_inc; do
		case $ny_g in
		/*) ny_globs="$ny_globs $ny_g" ;;
		*) ny_globs="$ny_globs /etc/ssh/$ny_g" ;;
		esac
	done
	set +f
	for ny_g in $ny_globs; do
		for ny_c in $ny_g; do
			[ -f "$ny_c" ] || continue
			[ "$ny_c" = "$NY_SSHD" ] && continue
			case "$NY_NL$ny_list$NY_NL" in
			*"$NY_NL$ny_c$NY_NL"*) continue ;;
			esac
			printf '%s\n' "$ny_c"
		done
	done
}

# --- generated files -------------------------------------------------------

ny_gen_ca() {
	for ny_gc_k in $NY_CA_B64; do
		printf 'ssh-ed25519 %s\n' "$ny_gc_k"
	done >"$1"
}

# ny_gen_sshd OUT ACCOUNTS...
ny_gen_sshd() {
	ny_gs_out=$1
	shift
	{
		printf '# Written by the Nyyrikki host setup (docs/07-ssh-target.md 5.7, D3, D4).\n'
		printf '# Re-run the setup to change it; --uninstall removes it.\n'
		printf 'TrustedUserCAKeys %s\n' "$NY_CA"
		printf 'AuthorizedPrincipalsFile %s/%%u\n' "$NY_PRINC"
		printf 'RevokedKeys %s\n' "$NY_KRL"
		# Among the global keywords, before any Match block, which may not
		# hold it (docs/08 D13).
		if [ "$NY_CERT_ON" = 1 ]; then
			printf 'HostCertificate %s\n' "$NY_HOSTCERT"
		fi
		for ny_gs_a in "$@"; do
			printf '\nMatch User %s\n' "$ny_gs_a"
			printf '\tAuthenticationMethods publickey\n'
			printf '\tAuthorizedKeysFile none\n'
			printf '\tAuthorizedKeysCommand none\n'
			printf '\tAuthorizedKeysCommandUser nobody\n'
			printf '\tAuthorizedPrincipalsCommand none\n'
			printf '\tAuthorizedPrincipalsCommandUser nobody\n'
			printf '\tPasswordAuthentication no\n'
			printf '\tKbdInteractiveAuthentication no\n'
			printf '\tHostbasedAuthentication no\n'
			printf '\tGSSAPIAuthentication no\n'
			printf '\tClientAliveInterval 5\n'
			printf '\tClientAliveCountMax 3\n'
		done
	} >"$ny_gs_out"
}

# ny_gen_principals OUT HUMAN
ny_gen_principals() {
	ny_gp_from=$(printf '%s' "$NY_SOURCES" | tr ' ' ',')
	printf 'restrict,pty,from="%s" nyyrikki:%s@%s\n' "$ny_gp_from" "$2" "$NY_TARGET" >"$1"
}

# ny_gen_sudoers OUT ACCOUNT
ny_gen_sudoers() {
	{
		printf 'Defaults:%s !requiretty\n' "$2"
		printf '%s ALL=(ALL) NOPASSWD: ALL\n' "$2"
	} >"$1"
}

# ny_gen_list OUT ACCOUNTS...
ny_gen_list() {
	ny_gl_out=$1
	shift
	: >"$ny_gl_out" || return 1
	for ny_gl_a in "$@"; do
		printf '%s\n' "$ny_gl_a"
	done >>"$ny_gl_out"
}

ny_gen_logind() {
	{
		printf '# Written by the Nyyrikki host setup (docs/07-ssh-target.md 5.7, D11).\n'
		printf '[Login]\n'
		printf 'KillUserProcesses=yes\n'
		printf 'KillOnlyUsers=%s\n' "$NY_ACCOUNTS"
	} >"$1"
}

ny_gen_scope() {
	{
		printf '# Written by the Nyyrikki host setup (docs/07-ssh-target.md 5.7, D11).\n'
		printf '[Scope]\n'
		printf 'TimeoutStopSec=5s\n'
	} >"$1"
}

# ny_gen_keys OUT B64...: one ssh-ed25519 line per key.
ny_gen_keys() {
	ny_gk_out=$1
	shift
	: >"$ny_gk_out" || return 1
	for ny_gk_k in "$@"; do
		printf 'ssh-ed25519 %s\n' "$ny_gk_k"
	done >>"$ny_gk_out"
}

# ny_gen_state OUT: pull.state as the setup leaves it: the mark is the
# setup's own ISSUED (docs/08 D13).
ny_gen_state() {
	printf 'ISSUED=%s\nBY=setup\n' "$NY_ISSUED" >"$1"
}

# ny_gen_pullconf OUT: what the pull reads (docs/08 D5).
ny_gen_pullconf() {
	{
		printf 'URL=%s\n' "$NY_URL"
		printf 'TARGET=%s\n' "$NY_TARGET"
		if [ "$NY_CACERT_SET" = 1 ]; then
			printf 'CACERT=%s\n' "$NY_SERVERCA"
			printf 'END=3\n'
		else
			printf 'END=2\n'
		fi
	} >"$1"
}

# ny_cron_minute: the schedule's minute offset, 0 to 14, from the target
# name, so that hosts don't all pull at once.
ny_cron_minute() {
	ny_cm=$(printf '%s' "$NY_TARGET" | cksum) || return 1
	ny_cm=${ny_cm%% *}
	case $ny_cm in
	'' | *[!0-9]*) return 1 ;;
	esac
	printf '%s' "$((ny_cm % 15))"
}

ny_gen_cron() {
	ny_gcr_m=$(ny_cron_minute) || return 1
	{
		printf '# Written by the Nyyrikki host setup (docs/08-ssh-onboarding.md D5): the\n'
		printf '# trust pull, every 15 minutes. Re-run the setup to change it; --uninstall removes it.\n'
		printf '%s-59/15 * * * * root %s\n' "$ny_gcr_m" "$NY_PULL"
	} >"$1"
}

ny_gen_periodic() {
	{
		printf '#!/bin/sh\n'
		printf '# Written by the Nyyrikki host setup (docs/08-ssh-onboarding.md D5): the\n'
		printf '# trust pull, every 15 minutes. Re-run the setup to change it; --uninstall removes it.\n'
		printf 'exec %s\n' "$NY_PULL"
	} >"$1"
}

# ny_gen_pull OUT: the trust pull (docs/08 D5). It is part of this body,
# so the published checksum covers it; nothing of it comes from the data
# lines or the server.
ny_gen_pull() {
	cat >"$1" <<'NYYRIKKI_PULL_END'
#!/bin/sh
# Nyyrikki trust pull (docs/08-ssh-onboarding.md D5). The Nyyrikki host
# setup wrote this file from its own body, and runs it from cron where it
# can. Re-run the setup to change it; --uninstall removes it.
#
# It fetches this target's trust bundle, checks its signature with
# ssh-keygen against the signers the setup wrote (never against the bundle
# being checked), checks every line, and then applies, taking access away
# first: revoked CA keys into the revocation list, the principals and
# sudoers files of humans no longer on the target, every Nyyrikki sudoers
# file with SUDO=false; last, the trusted CA keys and the bundle signers.
# It never reloads sshd (sshd reads those files at each login, docs/08 M4),
# never creates an account, writes a principals file for a new human,
# grants sudo or changes from=. On any failure it changes nothing more,
# logs, and exits non-zero.

pl_init() {
	PATH=/usr/sbin:/usr/bin:/sbin:/bin
	export PATH
	LC_ALL=C
	export LC_ALL
	umask 022
	PL_DIR=/etc/ssh/nyyrikki
	PL_CONF=$PL_DIR/pull.conf
	PL_STATE=$PL_DIR/pull.state
	PL_SIGNERS=$PL_DIR/signers.pub
	PL_CA=$PL_DIR/user_ca.pub
	PL_KRL=$PL_DIR/revoked.krl
	PL_PRINC=$PL_DIR/principals
	PL_LIST=$PL_DIR/accounts
	PL_SERVERCA=$PL_DIR/server-ca.pem
	PL_SUDO_PREFIX=/etc/sudoers.d/50-nyyrikki-
	PL_LOCK=/run/nyyrikki-ssh.lock
	PL_NS=nyyrikki-trust@v1
	PL_TMP=.nyyrikki-pull-new
	PL_WORK=
	PL_LOCKED=0
	PL_URL=
	PL_TARGET=
	PL_CACERT=
	PL_B_TARGET=
	PL_B_CA=
	PL_B_SIGNER=
	PL_B_REVOKED=
	PL_B_HUMANS=
	PL_B_SUDO=
	PL_B_ISSUED=
	PL_OLD=
	PL_SIGNED_BY=
	PL_MARK=
}

# pl_log MESSAGE: to syslog, where logger exists.
pl_log() {
	if command -v logger >/dev/null 2>&1; then
		logger -t nyyrikki "pull: $*" 2>/dev/null || :
	fi
}

# fail stops the pull. Never call it in a pipeline, a $(...) or a
# subshell: the exit would end only that subshell.
fail() {
	pl_log "failed: $*"
	printf 'nyyrikki-pull: %s\n' "$*" >&2 2>/dev/null || :
	pl_cleanup
	exit 1
}

pl_cleanup() {
	if [ -n "$PL_WORK" ] && [ -d "$PL_WORK" ]; then
		rm -rf -- "$PL_WORK" 2>/dev/null || :
	fi
	# The lock is released when this process exits (pl_lock).
	PL_LOCKED=0
}

# shellcheck disable=SC2329 # called from trap
pl_on_signal() {
	trap '' INT TERM HUP PIPE
	fail "interrupted by SIG$1"
}

# shellcheck disable=SC2329 # called from trap
pl_on_exit() {
	pl_status=$?
	trap '' INT TERM HUP PIPE
	pl_cleanup
	exit "$pl_status"
}

is_slug() {
	case $1 in
	'' | -* | *- | *[!a-z0-9-]*) return 1 ;;
	esac
	[ "${#1}" -le "$2" ]
}

is_b64() {
	case $1 in
	'' | *[!A-Za-z0-9+/=]*) return 1 ;;
	esac
	return 0
}

is_ms() {
	case $1 in
	[1-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) return 0 ;;
	esac
	return 1
}

is_secs() {
	case $1 in
	'' | 0?* | *[!0-9]*) return 1 ;;
	esac
	[ "${#1}" -le 12 ]
}

is_url() {
	[ "${#1}" -le 200 ] || return 1
	# grep -x matches per line: a value with a line break in it must not
	# pass on one good line (round 1 of #50).
	case $1 in *'
'*) return 1 ;; esac
	printf '%s\n' "$1" | grep -E -x -q 'https://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?'
}

has_word() {
	case " $1 " in
	*" $2 "*) return 0 ;;
	esac
	return 1
}

# pl_show VALUE: VALUE cut short, printable ASCII only, for messages.
pl_show() {
	printf '%.80s' "$1" | tr -c ' -~' '?'
}

# pl_key_b64 VALUE: the base64 of "ssh-ed25519 <base64>", or failure.
pl_key_b64() {
	case $1 in
	'ssh-ed25519 '*) pl_kb=${1#ssh-ed25519 } ;;
	*) return 1 ;;
	esac
	is_b64 "$pl_kb" || return 1
	printf '%s' "$pl_kb"
}

# pl_fp B64: the SHA256 fingerprint of an ed25519 key, or failure if it
# doesn't parse as one.
pl_fp() {
	printf 'ssh-ed25519 %s\n' "$1" >"$PL_WORK/fp.pub" || return 1
	pl_f=$(ssh-keygen -l -f "$PL_WORK/fp.pub" 2>/dev/null) || return 1
	case $pl_f in
	*'(ED25519)') ;;
	*) return 1 ;;
	esac
	pl_f=${pl_f#* }
	printf '%s' "${pl_f%% *}"
}

# pl_fps LIST: the fingerprints of the space-separated keys, for logs.
pl_fps() {
	pl_fs=
	for pl_fk in $1; do
		pl_ff=$(pl_fp "$pl_fk") || pl_ff='?'
		pl_fs="${pl_fs:+$pl_fs,}$pl_ff"
	done
	printf '%s' "${pl_fs:-none}"
}

# pl_revoked B64: 0 if the host's revocation list lists the key, 1 if
# not; anything else is an error.
pl_revoked() {
	printf 'ssh-ed25519 %s\n' "$1" >"$PL_WORK/q.pub" || return 2
	ssh-keygen -Q -f "$PL_KRL" "$PL_WORK/q.pub" >/dev/null 2>&1
	case $? in
	0) return 1 ;;
	1) return 0 ;;
	esac
	return 2
}

# pl_put SRC DEST MODE: installs SRC as DEST atomically.
pl_put() {
	pl_pt=${2%/*}/$PL_TMP
	rm -f -- "$pl_pt" &&
		cp -- "$1" "$pl_pt" &&
		chown 0:0 "$pl_pt" &&
		chmod "$3" "$pl_pt" &&
		mv -f -- "$pl_pt" "$2"
}

# pl_lock takes the setup's lock (ny_lock in the setup): a kernel lock
# on PL_LOCK, held on file descriptor 9 until this process exits.
pl_lock() {
	command -v flock >/dev/null 2>&1 || fail "flock not found"
	[ ! -L "$PL_LOCK" ] || fail "$PL_LOCK is a symbolic link"
	# A failed redirection on exec would end the shell without a word:
	# try it in a subshell first.
	( umask 077 && : >>"$PL_LOCK" ) 2>/dev/null || fail "can't open the lock $PL_LOCK"
	pl_lk_umask=$(umask)
	umask 077
	exec 9>>"$PL_LOCK"
	umask "$pl_lk_umask"
	chown 0:0 -- "$PL_LOCK" && chmod 0600 -- "$PL_LOCK" || fail "can't secure the lock $PL_LOCK"
	flock -n 9 || fail "a Nyyrikki setup or another pull is running; the next pull tries again"
	PL_LOCKED=1
}

# The host's own files, as the setup wrote them.
pl_read_host() {
	for pl_f in "$PL_CONF" "$PL_STATE" "$PL_SIGNERS" "$PL_CA" "$PL_KRL" "$PL_LIST"; do
		[ ! -L "$pl_f" ] || fail "$pl_f is a symbolic link"
		[ -f "$pl_f" ] || fail "$pl_f is missing: re-run the setup"
	done
	pl_n=0
	pl_end=0
	while IFS= read -r pl_l; do
		[ "$pl_end" = 0 ] || fail "$PL_CONF: a line after END"
		case $pl_l in
		URL=*)
			[ -z "$PL_URL" ] && is_url "${pl_l#URL=}" || fail "$PL_CONF: a bad or repeated URL"
			PL_URL=${pl_l#URL=}
			;;
		TARGET=*)
			[ -z "$PL_TARGET" ] && is_slug "${pl_l#TARGET=}" 63 || fail "$PL_CONF: a bad or repeated TARGET"
			PL_TARGET=${pl_l#TARGET=}
			;;
		CACERT=*)
			[ -z "$PL_CACERT" ] && [ "${pl_l#CACERT=}" = "$PL_SERVERCA" ] || fail "$PL_CONF: CACERT is not $PL_SERVERCA"
			PL_CACERT=$PL_SERVERCA
			;;
		END=*)
			[ "${pl_l#END=}" = "$pl_n" ] || fail "$PL_CONF is cut off or changed"
			pl_end=1
			continue
			;;
		*) fail "$PL_CONF: not a line of it: $(pl_show "$pl_l")" ;;
		esac
		pl_n=$((pl_n + 1))
	done <"$PL_CONF"
	[ "$pl_end" = 1 ] && [ -n "$PL_URL" ] && [ -n "$PL_TARGET" ] || fail "$PL_CONF is incomplete: re-run the setup"
	if [ -n "$PL_CACERT" ]; then
		[ -f "$PL_SERVERCA" ] && [ ! -L "$PL_SERVERCA" ] || fail "$PL_SERVERCA is missing: re-run the setup with --cacert"
	fi

	pl_by=
	while IFS= read -r pl_l; do
		case $pl_l in
		ISSUED=*) [ -z "$PL_MARK" ] && is_ms "${pl_l#ISSUED=}" || fail "$PL_STATE is malformed: re-run the setup"
			PL_MARK=${pl_l#ISSUED=} ;;
		APPLIED=*) is_secs "${pl_l#APPLIED=}" || fail "$PL_STATE is malformed: re-run the setup" ;;
		BY=setup | BY=pull) [ -z "$pl_by" ] || fail "$PL_STATE is malformed: re-run the setup"
			pl_by=${pl_l#BY=} ;;
		*) fail "$PL_STATE is malformed: re-run the setup" ;;
		esac
	done <"$PL_STATE"
	[ -n "$PL_MARK" ] && [ -n "$pl_by" ] || fail "$PL_STATE is malformed: re-run the setup"

	while IFS= read -r pl_l; do
		pl_b=$(pl_key_b64 "$pl_l") || fail "$PL_SIGNERS holds a line that isn't an ssh-ed25519 key: re-run the setup"
		has_word "$PL_OLD" "$pl_b" && fail "$PL_SIGNERS lists a key twice: re-run the setup"
		PL_OLD="${PL_OLD:+$PL_OLD }$pl_b"
	done <"$PL_SIGNERS"
	[ -n "$PL_OLD" ] || fail "$PL_SIGNERS lists no signer: re-run the setup"
}

pl_fetch() {
	set -- curl -fsS --proto =https --max-time 30 --max-filesize 1048576 -o "$PL_WORK/bundle"
	if [ -n "$PL_CACERT" ]; then
		set -- "$@" --cacert "$PL_CACERT"
	fi
	if ! "$@" "$PL_URL/hosts/$PL_TARGET/trust" 2>"$PL_WORK/curl.err"; then
		fail "fetching $PL_URL/hosts/$PL_TARGET/trust failed: $(head -c 300 "$PL_WORK/curl.err" | tr -c ' -~' ' ')"
	fi
	pl_size=$(wc -c <"$PL_WORK/bundle") || fail "can't read the bundle"
	[ "$pl_size" -le 1048576 ] || fail "the bundle is too large"
	pl_c=$(grep -c -x 'NYYRIKKI_SIGNATURE' "$PL_WORK/bundle")
	[ "$pl_c" = 1 ] || fail "the bundle has ${pl_c:-no} NYYRIKKI_SIGNATURE lines, not one: it is cut off or not a trust bundle"
	# Every byte before the NYYRIKKI_SIGNATURE line is signed (docs/08 D4);
	# what is verified is what is read below.
	awk -v d="$PL_WORK/data" -v s="$PL_WORK/sig" '
		f == 0 && $0 == "NYYRIKKI_SIGNATURE" { f = 1; next }
		f == 0 { print > d; next }
		{ print > s }' "$PL_WORK/bundle" || fail "can't split the bundle"
	[ -s "$PL_WORK/data" ] && [ -s "$PL_WORK/sig" ] || fail "the bundle has no data lines or no signature"
}

# pl_verify: which of this host's signers, minus the revoked ones, signed
# the bundle. Each signer gets a name of its own in the allowed-signers
# file, so the identity that verifies names the key.
pl_verify() {
	: >"$PL_WORK/allowed" || fail "can't write to $PL_WORK"
	pl_i=0
	pl_ok=
	for pl_k in $PL_OLD; do
		pl_revoked "$pl_k"
		case $? in
		0) continue ;;
		1) ;;
		*) fail "can't read $PL_KRL" ;;
		esac
		pl_i=$((pl_i + 1))
		printf 'signer-%s namespaces="%s" ssh-ed25519 %s\n' "$pl_i" "$PL_NS" "$pl_k" >>"$PL_WORK/allowed" || fail "can't write to $PL_WORK"
		pl_ok="${pl_ok:+$pl_ok }$pl_k"
	done
	[ -n "$pl_ok" ] || fail "every signer this host has is revoked: re-run the setup"
	pl_i=0
	for pl_k in $pl_ok; do
		pl_i=$((pl_i + 1))
		if ssh-keygen -Y verify -f "$PL_WORK/allowed" -I "signer-$pl_i" -n "$PL_NS" -s "$PL_WORK/sig" <"$PL_WORK/data" >/dev/null 2>&1; then
			PL_SIGNED_BY=$pl_k
			return 0
		fi
	done
	fail "the bundle's signature doesn't verify with any of this host's signers ($(pl_fps "$pl_ok")): refused"
}

# pl_read_bundle: every data line, checked as the setup checks its own.
pl_read_bundle() {
	pl_n=0
	pl_end=0
	while IFS= read -r pl_l; do
		[ "$pl_end" = 0 ] || fail "refused: a data line after END"
		case $pl_l in
		[A-Z_]*=*) ;;
		*) fail "refused: not a data line: $(pl_show "$pl_l")" ;;
		esac
		pl_name=${pl_l%%=*}
		pl_val=${pl_l#*=}
		case $pl_name in
		*[!A-Z_]*) fail "refused: not a data line: $(pl_show "$pl_l")" ;;
		esac
		case $pl_name in
		TARGET)
			[ -z "$PL_B_TARGET" ] || fail "refused: TARGET given twice"
			is_slug "$pl_val" 63 || fail "refused: TARGET is not a target name"
			PL_B_TARGET=$pl_val
			;;
		CA_KEY | SIGNER_KEY | REVOKED_CA_KEY)
			pl_b=$(pl_key_b64 "$pl_val") || fail "refused: $pl_name is not an ssh-ed25519 key of base64 characters: $(pl_show "$pl_val")"
			case $pl_name in
			CA_KEY)
				has_word "$PL_B_CA" "$pl_b" && fail "refused: a CA_KEY given twice"
				PL_B_CA="${PL_B_CA:+$PL_B_CA }$pl_b"
				;;
			SIGNER_KEY)
				has_word "$PL_B_SIGNER" "$pl_b" && fail "refused: a SIGNER_KEY given twice"
				PL_B_SIGNER="${PL_B_SIGNER:+$PL_B_SIGNER }$pl_b"
				;;
			*)
				has_word "$PL_B_REVOKED" "$pl_b" && fail "refused: a REVOKED_CA_KEY given twice"
				PL_B_REVOKED="${PL_B_REVOKED:+$PL_B_REVOKED }$pl_b"
				;;
			esac
			;;
		HUMAN)
			is_slug "$pl_val" 29 || fail "refused: HUMAN is not a human ID: $(pl_show "$pl_val")"
			has_word "$PL_B_HUMANS" "$pl_val" && fail "refused: HUMAN $pl_val given twice"
			PL_B_HUMANS="${PL_B_HUMANS:+$PL_B_HUMANS }$pl_val"
			;;
		SUDO)
			[ -z "$PL_B_SUDO" ] || fail "refused: SUDO given twice"
			case $pl_val in
			true | false) PL_B_SUDO=$pl_val ;;
			*) fail "refused: SUDO is neither true nor false" ;;
			esac
			;;
		ISSUED)
			[ -z "$PL_B_ISSUED" ] || fail "refused: ISSUED given twice"
			is_ms "$pl_val" || fail "refused: ISSUED is not a time in Unix milliseconds"
			PL_B_ISSUED=$pl_val
			;;
		END)
			[ "$pl_val" = "$pl_n" ] || fail "refused: END=$(pl_show "$pl_val") but $pl_n lines came before it: the bundle is cut off or changed"
			pl_end=1
			continue
			;;
		*) fail "refused: unknown data line name: $(pl_show "$pl_name")" ;;
		esac
		pl_n=$((pl_n + 1))
	done <"$PL_WORK/data"
	[ "$pl_end" = 1 ] || fail "refused: no END line: the bundle is cut off"
	[ -n "$PL_B_TARGET" ] && [ -n "$PL_B_CA" ] && [ -n "$PL_B_SIGNER" ] && [ -n "$PL_B_HUMANS" ] &&
		[ -n "$PL_B_SUDO" ] && [ -n "$PL_B_ISSUED" ] || fail "refused: the bundle lacks a TARGET, CA_KEY, SIGNER_KEY, HUMAN, SUDO or ISSUED line"
	[ "$PL_B_TARGET" = "$PL_TARGET" ] || fail "refused: the bundle is for target $PL_B_TARGET, not $PL_TARGET"
	for pl_k in $PL_B_CA $PL_B_REVOKED; do
		pl_fp "$pl_k" >/dev/null || fail "refused: a key in the bundle doesn't parse as an ed25519 key"
	done
	for pl_k in $PL_B_SIGNER; do
		has_word "$PL_B_CA" "$pl_k" || fail "refused: a SIGNER_KEY is not among the CA_KEYs (docs/08 D4)"
		has_word "$PL_B_REVOKED" "$pl_k" && fail "refused: a SIGNER_KEY is also a REVOKED_CA_KEY"
	done
	pl_now=$(date +%s) || fail "can't read the clock"
	is_secs "$pl_now" || fail "can't read the clock"
	pl_limit=$((pl_now * 1000 + 600000))
	[ "$PL_B_ISSUED" -gt "$PL_MARK" ] || fail "refused: the bundle was issued at $PL_B_ISSUED, not after the last one applied ($PL_MARK): a replay, or the server's clock went back"
	[ "$PL_B_ISSUED" -le "$pl_limit" ] || fail "refused: the bundle was issued at $PL_B_ISSUED, more than 10 minutes ahead of this host's clock ($((pl_now * 1000))): set the clock (NTP)"
	return 0
}

# pl_signers: the bundle's signers relate to the host's in one of
# docs/08 D5's three ways, or the whole bundle is refused.
pl_signers() {
	pl_new_in_old=1
	for pl_k in $PL_B_SIGNER; do
		has_word "$PL_OLD" "$pl_k" || pl_new_in_old=0
	done
	pl_old_in_new=1
	for pl_k in $PL_OLD; do
		has_word "$PL_B_SIGNER" "$pl_k" || pl_old_in_new=0
	done
	if [ "$pl_new_in_old" = 1 ] && [ "$pl_old_in_new" = 1 ]; then
		PL_RELATION=none
	elif [ "$pl_old_in_new" = 1 ]; then
		# A stage: signed by a key the host already has (always so: only
		# those verify).
		has_word "$PL_OLD" "$PL_SIGNED_BY" || fail "refused: a stage signed by a key this host doesn't have"
		PL_RELATION=stage
	elif [ "$pl_new_in_old" = 1 ]; then
		has_word "$PL_B_SIGNER" "$PL_SIGNED_BY" || fail "refused: a promote must be signed by a key it keeps; signed by $(pl_fps "$PL_SIGNED_BY"), keeping $(pl_fps "$PL_B_SIGNER")"
		PL_RELATION=promote
	else
		fail "refused: the bundle's signers ($(pl_fps "$PL_B_SIGNER")) are neither a stage nor a promote of this host's ($(pl_fps "$PL_OLD")); re-run the setup (docs/08 D5, §5.4)"
	fi
}

# pl_apply takes access away first, then replaces the trusted keys and the
# signers.
pl_apply() {
	# Revoked CA keys into the revocation list.
	: >"$PL_WORK/revoke.pub" || fail "can't write to $PL_WORK"
	for pl_k in $PL_B_REVOKED; do
		pl_revoked "$pl_k"
		case $? in
		0) ;;
		1) printf 'ssh-ed25519 %s\n' "$pl_k" >>"$PL_WORK/revoke.pub" || fail "can't write to $PL_WORK" ;;
		*) fail "can't read $PL_KRL" ;;
		esac
	done
	if [ -s "$PL_WORK/revoke.pub" ]; then
		cp -- "$PL_KRL" "$PL_WORK/krl" &&
			ssh-keygen -q -k -u -f "$PL_WORK/krl" "$PL_WORK/revoke.pub" &&
			pl_put "$PL_WORK/krl" "$PL_KRL" 0644 || fail "can't add the revoked keys to $PL_KRL"
		pl_log "revoked CA keys added to $PL_KRL: $(pl_fps "$(sed 's/^ssh-ed25519 //' "$PL_WORK/revoke.pub" | tr '\n' ' ')")"
	fi

	# Humans no longer on the target, and sudo.
	pl_listed=
	while IFS= read -r pl_a; do
		case $pl_a in
		ny-*) is_slug "${pl_a#ny-}" 29 || fail "$PL_LIST holds a line that isn't a Nyyrikki account" ;;
		*) fail "$PL_LIST holds a line that isn't a Nyyrikki account" ;;
		esac
		pl_listed="${pl_listed:+$pl_listed }$pl_a"
	done <"$PL_LIST"
	for pl_a in $pl_listed; do
		has_word "$PL_B_HUMANS" "${pl_a#ny-}" && continue
		for pl_f in "$PL_SUDO_PREFIX$pl_a" "$PL_PRINC/$pl_a"; do
			if [ -e "$pl_f" ] || [ -L "$pl_f" ]; then
				rm -f -- "$pl_f" || fail "can't remove $pl_f"
				pl_log "removed $pl_f: ${pl_a#ny-} is no longer a human of $PL_TARGET; re-run the setup to delete $pl_a"
			fi
		done
	done
	if [ "$PL_B_SUDO" = false ]; then
		for pl_f in "$PL_SUDO_PREFIX"*; do
			[ -e "$pl_f" ] || [ -L "$pl_f" ] || continue
			rm -f -- "$pl_f" || fail "can't remove $pl_f"
			pl_log "removed $pl_f: $PL_TARGET no longer gives sudo"
		done
	fi
	# What would add access waits for an administrator.
	for pl_h in $PL_B_HUMANS; do
		if ! has_word "$pl_listed" "ny-$pl_h"; then
			pl_log "re-run the setup to add ny-$pl_h: the pull never creates an account"
		elif [ "$PL_B_SUDO" = true ] && [ ! -e "$PL_SUDO_PREFIX"ny-"$pl_h" ] && [ -e "$PL_PRINC/ny-$pl_h" ]; then
			pl_log "re-run the setup to add sudo for ny-$pl_h: the pull never grants sudo"
		fi
	done

	# Last, the trusted keys, then the signers.
	: >"$PL_WORK/ca" || fail "can't write to $PL_WORK"
	pl_cas=
	for pl_k in $PL_B_CA; do
		has_word "$PL_B_REVOKED" "$pl_k" && continue
		printf 'ssh-ed25519 %s\n' "$pl_k" >>"$PL_WORK/ca" || fail "can't write to $PL_WORK"
		pl_cas="${pl_cas:+$pl_cas }$pl_k"
	done
	[ -n "$pl_cas" ] || fail "refused: every CA key in the bundle is revoked"
	# Small files of keys: compared as text (cmp isn't on every host).
	if [ "$(cat "$PL_WORK/ca")" != "$(cat "$PL_CA")" ]; then
		pl_old_ca=$(sed 's/^ssh-ed25519 //' "$PL_CA" | tr '\n' ' ')
		pl_put "$PL_WORK/ca" "$PL_CA" 0644 || fail "can't write $PL_CA"
		pl_log "trusted CA keys changed from $(pl_fps "$pl_old_ca") to $(pl_fps "$pl_cas")"
	fi
	if [ "$PL_RELATION" != none ]; then
		: >"$PL_WORK/signers" || fail "can't write to $PL_WORK"
		for pl_k in $PL_B_SIGNER; do
			printf 'ssh-ed25519 %s\n' "$pl_k" >>"$PL_WORK/signers" || fail "can't write to $PL_WORK"
		done
		pl_put "$PL_WORK/signers" "$PL_SIGNERS" 0644 || fail "can't write $PL_SIGNERS"
		pl_msg="bundle signers changed ($PL_RELATION, signed by $(pl_fps "$PL_SIGNED_BY")) from $(pl_fps "$PL_OLD") to $(pl_fps "$PL_B_SIGNER")"
		pl_log "$pl_msg"
		printf 'nyyrikki-pull: %s\n' "$pl_msg" 2>/dev/null || :
	fi
	printf 'ISSUED=%s\nAPPLIED=%s\nBY=pull\n' "$PL_B_ISSUED" "$pl_now" >"$PL_WORK/state" &&
		pl_put "$PL_WORK/state" "$PL_STATE" 0644 || fail "can't write $PL_STATE"
}

pull_main() {
	pl_init
	set -u
	trap 'pl_on_signal INT' INT
	trap 'pl_on_signal TERM' TERM
	trap 'pl_on_signal HUP' HUP
	trap 'pl_on_signal PIPE' PIPE
	trap 'pl_on_exit' EXIT
	[ "$#" = 0 ] || fail "takes no arguments"
	[ "$(id -u)" = 0 ] || fail "run as root"
	for pl_t in curl ssh-keygen awk grep sed; do
		command -v "$pl_t" >/dev/null 2>&1 || fail "$pl_t not found"
	done
	pl_lock
	PL_WORK=$(mktemp -d "${TMPDIR:-/tmp}/nyyrikki-pull.XXXXXX") || fail "can't create a work directory"
	chmod 0700 "$PL_WORK" || fail "can't create a work directory"
	pl_read_host
	pl_fetch
	pl_verify
	pl_read_bundle
	pl_signers
	pl_apply
	pl_log "applied the bundle issued at $PL_B_ISSUED"
	trap - EXIT
	pl_cleanup
	exit 0
}

pull_main "$@"
NYYRIKKI_PULL_END
}

# ny_print_file PATH MODE GENERATED: --dry-run's listing.
ny_print_file() {
	say "would write $1 (mode $2):"
	sed 's/^/    /' "$3" 2>/dev/null || :
}

# ny_read_state FILE: sets NY_MARK, NY_MARK_AT and NY_MARK_BY from FILE,
# a pull.state; fails if FILE isn't one.
ny_read_state() {
	NY_MARK=
	NY_MARK_AT=
	NY_MARK_BY=
	while IFS= read -r ny_rs_l; do
		case $ny_rs_l in
		ISSUED=*)
			[ -z "$NY_MARK" ] && is_ms "${ny_rs_l#ISSUED=}" || return 1
			NY_MARK=${ny_rs_l#ISSUED=}
			;;
		APPLIED=*)
			[ -z "$NY_MARK_AT" ] && is_secs "${ny_rs_l#APPLIED=}" || return 1
			NY_MARK_AT=${ny_rs_l#APPLIED=}
			;;
		BY=setup | BY=pull)
			[ -z "$NY_MARK_BY" ] || return 1
			NY_MARK_BY=${ny_rs_l#BY=}
			;;
		*) return 1 ;;
		esac
	done <"$1"
	[ -n "$NY_MARK" ] && [ -n "$NY_MARK_BY" ]
}

# ny_clock: NY_NOW_S, the host's time, and NY_LIMIT_MS, 10 minutes ahead
# of it in milliseconds (docs/08 D5, D13).
ny_clock() {
	NY_NOW_S=$(date +%s) || NY_NOW_S=
	is_secs "$NY_NOW_S" || die "refused: can't read this host's clock (date +%s)"
	NY_LIMIT_MS=$((NY_NOW_S * 1000 + 600000))
}

# ny_date SECONDS: a readable UTC time, or SECONDS if date can't.
ny_date() {
	date -u -d "@$1" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || printf '%s (Unix seconds)' "$1"
}

# ny_detect_schedule sets NY_SCHED to how the pull can be run (docs/08
# D5, M3): cron.d where /etc/cron.d exists and a cron that isn't BusyBox's
# (which ignores it) is installed; periodic where /etc/periodic/15min
# exists and root's crontab runs it; none otherwise, or without curl (M6).
ny_detect_schedule() {
	NY_SCHED=none
	NY_SCHED_WHY=
	if ! command -v curl >/dev/null 2>&1; then
		NY_SCHED_WHY="curl isn't installed (BusyBox wget can't be given a CA file, docs/08 M6)"
		return 0
	fi
	if [ -d /etc/cron.d ] && [ ! -L /etc/cron.d ]; then
		for ny_ds_c in cron crond; do
			ny_ds_p=$(command -v "$ny_ds_c" 2>/dev/null) || continue
			ny_ds_r=$(readlink -f -- "$ny_ds_p" 2>/dev/null) || ny_ds_r=$ny_ds_p
			case ${ny_ds_r##*/} in
			busybox*) continue ;;
			esac
			NY_SCHED=cron.d
			# Installed isn't running: on a systemd host, say so when no
			# cron unit is enabled (round 1 of #50).
			if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1 &&
				! systemctl is-enabled --quiet cron.service crond.service cronie.service 2>/dev/null; then
				NY_SCHED_WHY="warning: no cron unit is enabled (systemctl enable --now cron or crond), so nothing runs the pull yet"
			fi
			return 0
		done
	fi
	if [ -d /etc/periodic/15min ] && [ ! -L /etc/periodic/15min ] && command -v run-parts >/dev/null 2>&1; then
		for ny_ds_f in /etc/crontabs/root /var/spool/cron/crontabs/root /var/spool/cron/root; do
			[ -f "$ny_ds_f" ] || continue
			if grep -E -q '^[^#]*[[:space:]]run-parts[[:space:]]+/etc/periodic/15min/?([[:space:]]|$)' "$ny_ds_f"; then
				NY_SCHED=periodic
				return 0
			fi
		done
	fi
	NY_SCHED_WHY="no cron that reads /etc/cron.d, and no root crontab that runs /etc/periodic/15min"
}

# ny_check_issued: the setup's ISSUED is at most 10 minutes ahead of the
# host's clock, and not older than the last bundle applied, unless
# --reset-pull-state (docs/08 D13).
ny_check_issued() {
	ny_clock
	if [ "$NY_ISSUED" -gt "$NY_LIMIT_MS" ]; then
		die "refused: this setup script was issued at $NY_ISSUED (Unix milliseconds), more than 10 minutes ahead of this host's clock ($((NY_NOW_S * 1000))): set the clock (NTP), then fetch the script again"
	fi
	if [ -e "$NY_STATE" ]; then
		if ! ny_read_state "$NY_STATE"; then
			[ "$NY_RESET" = 1 ] || die "refused: $NY_STATE is malformed; run the setup with --reset-pull-state to replace it"
			say "check: $NY_STATE is malformed; --reset-pull-state replaces it"
		elif [ "$NY_MARK" -le "$NY_LIMIT_MS" ] && [ "$NY_MARK" -gt "$NY_ISSUED" ]; then
			if [ "$NY_RESET" = 0 ]; then
				die "refused: this setup script is older than the last bundle applied; fetch it again. The last bundle applied was issued at $NY_MARK (Unix milliseconds), this script at $NY_ISSUED. To set the mark to this script's anyway, as the leak procedure does (docs/08 5.4), run it with --reset-pull-state"
			fi
			say "check: the last bundle applied was issued at $NY_MARK, after this script ($NY_ISSUED); --reset-pull-state sets the mark to this script's"
		elif [ "$NY_MARK" -gt "$NY_LIMIT_MS" ]; then
			say "check: the last bundle applied claims a time more than 10 minutes ahead of this host's clock ($NY_MARK); this run forgets it"
		fi
	fi
	say "check: this script was issued at $NY_ISSUED; this host's clock is $((NY_NOW_S * 1000))"
}

# --- step 1: checks ---------------------------------------------------------

ny_check() {
	[ "$(id -u)" = 0 ] || die "refused: run as root (sudo sh setup.sh)"
	[ "$NY_DRY" = 1 ] || ny_lock

	NY_SSHD_BIN=$(command -v sshd) || NY_SSHD_BIN=
	[ -n "$NY_SSHD_BIN" ] || die "refused: sshd not found"
	for ny_t in ssh-keygen getent useradd userdel pgrep awk sed cut tr stat mktemp; do
		command -v "$ny_t" >/dev/null 2>&1 || die "refused: $ny_t not found"
	done
	ny_v=$("$NY_SSHD_BIN" -V 2>&1) || :
	case $ny_v in
	*OpenSSH_*) ;;
	*) ny_v=$(ssh -V 2>&1) || : ;;
	esac
	ny_v=$(printf '%s\n' "$ny_v" | sed -n 's/.*OpenSSH_\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1 \2/p' | head -n 1)
	ny_major=${ny_v%% *}
	case $ny_major in
	'' | *[!0-9]*) die "refused: can't tell the OpenSSH version" ;;
	esac
	[ "$ny_major" -ge 9 ] || die "refused: OpenSSH $ny_major is older than 9.0"
	say "check: OpenSSH $ny_major.${ny_v#* }"

	ny_first=$(awk '{ sub(/#.*/, "") } NF { print; exit }' /etc/ssh/sshd_config 2>/dev/null) || ny_first=
	ny_ok=0
	ny_kw=${ny_first%%[ 	=]*}
	case $ny_kw in
	[Ii][Nn][Cc][Ll][Uu][Dd][Ee])
		set -f
		for ny_w in ${ny_first#*[ 	=]}; do
			[ "$ny_w" = "$NY_SSHD_DIR/*.conf" ] && ny_ok=1
		done
		set +f
		;;
	esac
	[ "$ny_ok" = 1 ] || die "refused: the first line of /etc/ssh/sshd_config that isn't a comment doesn't include $NY_SSHD_DIR/*.conf"
	[ -d "$NY_SSHD_DIR" ] || die "refused: $NY_SSHD_DIR doesn't exist"
	say "check: sshd_config includes $NY_SSHD_DIR/*.conf first"

	ny_t=$("$NY_SSHD_BIN" -t 2>&1) || die "refused: sshd -t fails on the current configuration: $ny_t"
	ny_global=$("$NY_SSHD_BIN" -T 2>&1) || die "refused: sshd -T fails: $ny_global"
	for ny_kv in "trustedusercakeys $NY_CA" "authorizedprincipalsfile $NY_PRINC/%u" "revokedkeys $NY_KRL"; do
		ny_k=${ny_kv%% *}
		ny_line=$(printf '%s\n' "$ny_global" | grep "^$ny_k ") || ny_line="$ny_k none"
		[ "$ny_line" = "$ny_k none" ] || [ "$ny_line" = "$ny_kv" ] ||
			die "refused: sshd already has $ny_line"
	done
	case "$NY_NL$ny_global" in
	*"${NY_NL}gssapiauthentication "*) NY_GSSAPI=1 ;;
	esac
	if [ "$NY_ENROLL_SET" = 1 ]; then
		# docs/08 D7, D8: the certificate is for the host's ed25519 key,
		# which sshd must use.
		command -v curl >/dev/null 2>&1 || die "refused: --enroll needs curl"
		[ -f "$NY_HOSTKEY.pub" ] && [ ! -L "$NY_HOSTKEY.pub" ] ||
			die "refused: --enroll needs the ed25519 host key $NY_HOSTKEY.pub (docs/08 D8); without one, pin the host's keys instead"
		printf '%s\n' "$ny_global" | grep -F -x -q "hostkey $NY_HOSTKEY" ||
			die "refused: --enroll: sshd doesn't use $NY_HOSTKEY as a host key, so it couldn't present a certificate for it"
	fi
	ny_files=$(ny_config_files) || die "refused: can't list sshd's configuration files"
	ny_hits=$(printf '%s\n' "$ny_files" | while IFS= read -r ny_c; do
		[ -f "$ny_c" ] || continue
		awk -v f="$ny_c" '{ sub(/#.*/, ""); n = split($0, w, /[ \t=]+/); s = 1; if (w[1] == "") s = 2
			k = tolower(w[s]); if (k == "trustedusercakeys" || k == "authorizedprincipalsfile" || k == "revokedkeys") print f ":" NR ": " w[s] }' "$ny_c"
	done)
	[ -z "$ny_hits" ] || die "refused: another sshd configuration sets a certificate trust keyword: $ny_hits"
	say "check: sshd trusts no other user CA, principals file or revocation list"

	for ny_p in "$NY_DIR" "$NY_PRINC"; do
		if [ -e "$ny_p" ] || [ -L "$ny_p" ]; then
			[ -d "$ny_p" ] && [ ! -L "$ny_p" ] || die "refused: $ny_p isn't a directory"
			ny_st=$(stat -c '%u %a' -- "$ny_p")
			case $ny_st in
			'0 '[0-7][0145][0145]) ;;
			*) die "refused: $ny_p isn't owned by root or is writable by others (sshd would refuse it)" ;;
			esac
		fi
	done
	for ny_p in "$NY_CA" "$NY_KRL" "$NY_LIST" "$NY_SSHD" "$NY_LOGIND" "$NY_SCOPE" "$NY_SIGNERS" "$NY_STATE" \
		"$NY_PULL" "$NY_PULLCONF" "$NY_SERVERCA" "$NY_HOSTCERT" "$NY_CRON" "$NY_PERIODIC"; do
		[ ! -L "$ny_p" ] || die "refused: $ny_p is a symbolic link"
		[ ! -e "$ny_p" ] || [ -f "$ny_p" ] || die "refused: $ny_p isn't a regular file"
	done

	# The CA keys: each must parse and be ed25519.
	for ny_k in $NY_CA_B64; do
		printf 'ssh-ed25519 %s\n' "$ny_k" >"$NY_WORK/ca-check.pub" || die "can't write to $NY_WORK"
		ny_fp=$(ssh-keygen -l -f "$NY_WORK/ca-check.pub" 2>&1) || die "refused: a CA_KEY doesn't parse: $ny_fp"
		case $ny_fp in
		*'(ED25519)') ;;
		*) die "refused: a CA_KEY isn't ed25519: $ny_fp" ;;
		esac
		say "check: user CA key ${ny_fp% (ED25519)}"
	done
	for ny_k in $NY_REVOKED_B64; do
		printf 'ssh-ed25519 %s\n' "$ny_k" >"$NY_WORK/ca-check.pub" || die "can't write to $NY_WORK"
		ny_fp=$(ssh-keygen -l -f "$NY_WORK/ca-check.pub" 2>&1) || die "refused: a REVOKED_CA_KEY doesn't parse: $ny_fp"
		case $ny_fp in
		*'(ED25519)') ;;
		*) die "refused: a REVOKED_CA_KEY isn't ed25519: $ny_fp" ;;
		esac
		say "check: revoked user CA key ${ny_fp% (ED25519)}"
	done
	ny_check_issued
	if [ "$NY_CACERT_SET" = 1 ]; then
		[ -f "$NY_CACERT" ] && [ -r "$NY_CACERT" ] || die "refused: --cacert $(ny_show "$NY_CACERT") isn't a readable file"
		ny_sz=$(wc -c <"$NY_CACERT") || die "refused: can't read --cacert $(ny_show "$NY_CACERT")"
		[ "$ny_sz" -le 1048576 ] || die "refused: --cacert $(ny_show "$NY_CACERT") is larger than 1 MiB"
		grep -q -e '-----BEGIN CERTIFICATE-----' "$NY_CACERT" || die "refused: --cacert $(ny_show "$NY_CACERT") holds no PEM certificate"
	fi
	if [ -f "$NY_HOSTCERT" ]; then
		NY_CERT_ON=1
		say "check: $NY_HOSTCERT exists; the drop-in names it (HostCertificate)"
	fi
	ny_detect_schedule
	say "check: pull: $NY_SCHED${NY_SCHED_WHY:+ ($NY_SCHED_WHY)}"
	if [ -f "$NY_KRL" ]; then
		ny_fp=$(ssh-keygen -Q -f "$NY_KRL" "$NY_WORK/ca-check.pub" 2>&1)
		case $? in
		0 | 1) ;;
		*) die "refused: $NY_KRL isn't a valid key revocation list: $ny_fp" ;;
		esac
		ny_krl_trusted
	fi

	# The accounts list.
	if [ -f "$NY_LIST" ]; then
		while IFS= read -r ny_a; do
			case $ny_a in
			ny-*) is_slug "${ny_a#ny-}" 29 || die "refused: $NY_LIST holds a line that isn't a Nyyrikki account: $(ny_show "$ny_a")" ;;
			*) die "refused: $NY_LIST holds a line that isn't a Nyyrikki account: $(ny_show "$ny_a")" ;;
			esac
			has_word "$NY_LISTED" "$ny_a" || NY_LISTED="${NY_LISTED:+$NY_LISTED }$ny_a"
		done <"$NY_LIST"
	fi

	# sudo, if the target gives it.
	if [ "$NY_SUDO" = true ]; then
		command -v visudo >/dev/null 2>&1 || die "refused: SUDO=true but visudo isn't installed"
		[ -d /etc/sudoers.d ] || die "refused: SUDO=true but /etc/sudoers.d doesn't exist"
		grep -E -q '^[#@]includedir[[:space:]]+/etc/sudoers\.d[[:space:]]*$' /etc/sudoers ||
			die "refused: SUDO=true but /etc/sudoers doesn't include /etc/sudoers.d"
	fi

	# logind: no configuration file but Nyyrikki's own sets the kill settings.
	if [ -d /run/systemd/system ]; then
		NY_SYSTEMD=1
		command -v systemctl >/dev/null 2>&1 || die "refused: systemd host without systemctl"
		ny_cat=$(systemd-analyze cat-config systemd/logind.conf 2>/dev/null) ||
			die "refused: can't read logind's configuration (systemd-analyze cat-config systemd/logind.conf)"
		ny_hits=$(printf '%s\n' "$ny_cat" | awk -v ours="$NY_LOGIND" '
			(NR == 1 || prev == "") && /^# \/[^ ]+$/ { f = substr($0, 3); prev = $0; next }
			{ prev = $0 }
			f != ours && /^[ \t]*(KillUserProcesses|KillOnlyUsers|KillExcludeUsers)[ \t]*=/ { print f ": " $0 }')
		[ -z "$ny_hits" ] || die "refused: another logind configuration sets a kill setting: $ny_hits"
		[ -f "$NY_LOGIND" ] && NY_LOGIND_OURS=1
		say "check: no logind configuration but Nyyrikki's sets KillUserProcesses, KillOnlyUsers or KillExcludeUsers"
	fi

	# The accounts: current ones must be new or unchanged since the setup
	# created them; stale ones (listed, no longer in the data lines) go.
	for ny_a in $NY_ACCOUNTS; do
		if account_exists "$ny_a"; then
			has_word "$NY_LISTED" "$ny_a" ||
				die "refused: the account $ny_a exists but the setup didn't create it (it isn't in $NY_LIST)"
			ny_why=$(account_check "$ny_a") || die "refused: the account $ny_a changed since the setup created it: $ny_why"
		else
			if [ -e "/home/$ny_a" ] || [ -L "/home/$ny_a" ]; then
				die "refused: /home/$ny_a exists without its account; remove it first"
			fi
			NY_CREATE="${NY_CREATE:+$NY_CREATE }$ny_a"
		fi
	done
	for ny_a in $NY_LISTED; do
		has_word "$NY_ACCOUNTS" "$ny_a" && continue
		NY_STALE="${NY_STALE:+$NY_STALE }$ny_a"
		if account_exists "$ny_a"; then
			NY_STALE_EXISTING="${NY_STALE_EXISTING:+$NY_STALE_EXISTING }$ny_a"
		fi
	done
	say "check: accounts ${NY_ACCOUNTS}${NY_CREATE:+ (to create: $NY_CREATE)}${NY_STALE:+ (to remove: $NY_STALE)}"
}

# --- steps 2 to 8 ------------------------------------------------------------

# Step 2: take away. Never undone by a rollback: what it removes, the
# target no longer grants.
ny_take_away() {
	for ny_a in $NY_STALE; do
		ny_drop "$NY_SUDO_PREFIX$ny_a"
	done
	if [ "$NY_SUDO" = false ]; then
		for ny_a in $NY_ACCOUNTS; do
			ny_drop "$NY_SUDO_PREFIX$ny_a"
		done
	fi
	for ny_a in $NY_STALE; do
		ny_drop "$NY_PRINC/$ny_a"
	done
	ny_revoke
}

# ny_revoke adds each REVOKED_CA_KEY to an existing revocation list
# (docs/08 D13). Like the rest of step 2, a rollback leaves it: the
# values no longer trust those keys. Step 3 writes a missing list with
# them included.
# ny_krl_trusted refuses when the host's revocation list lists a key this
# script's values trust (a CA_KEY or SIGNER_KEY). The list only grows, and
# a bundle signed by a leaked key could have added the staged key to it:
# without this, the leak recovery's re-run (docs/08 §5.4) would succeed
# and leave the host refusing every Nyyrikki login (round 1 of #50). The
# list isn't rebuilt here, since that would drop revocations added by hand.
ny_krl_trusted() {
	ny_kt_bad=
	for ny_kt_k in $NY_CA_B64 $NY_SIGNER_B64; do
		printf 'ssh-ed25519 %s\n' "$ny_kt_k" >"$NY_WORK/kt.pub" || die "can't write to $NY_WORK"
		ssh-keygen -Q -f "$NY_KRL" "$NY_WORK/kt.pub" >/dev/null 2>&1
		case $? in
		0) ;;
		1)
			ny_kt_fp=$(ssh-keygen -l -f "$NY_WORK/kt.pub" | cut -d' ' -f2) || die "can't read a CA key"
			case " $ny_kt_bad " in
			*" $ny_kt_fp "*) ;;
			*) ny_kt_bad="${ny_kt_bad:+$ny_kt_bad }$ny_kt_fp" ;;
			esac
			;;
		*) die "refused: can't read $NY_KRL" ;;
		esac
	done
	[ -z "$ny_kt_bad" ] || die "refused: $NY_KRL, the host's revocation list, lists a key this script trusts: $ny_kt_bad. A revoked key, or one a leaked key revoked through a bundle, stays revoked until the list is rebuilt: rebuild it from the revoked keys only (ssh-keygen -k -f $NY_KRL <each revoked public key>; see docs/setup/ssh-hosts.md), then run this again"
}

ny_revoke() {
	[ -f "$NY_KRL" ] && [ -n "$NY_REVOKED_B64" ] || return 0
	: >"$NY_WORK/revoke.pub" || die "can't write to $NY_WORK"
	for ny_k in $NY_REVOKED_B64; do
		printf 'ssh-ed25519 %s\n' "$ny_k" >"$NY_WORK/q.pub" || die "can't write to $NY_WORK"
		ssh-keygen -Q -f "$NY_KRL" "$NY_WORK/q.pub" >/dev/null 2>&1
		case $? in
		0) cat "$NY_WORK/q.pub" >>"$NY_WORK/revoke.pub" || die "can't write to $NY_WORK" ;;
		1) ;;
		*) die "can't read $NY_KRL" ;;
		esac
	done
	[ -s "$NY_WORK/revoke.pub" ] || return 0
	NY_CHANGED=1
	ny_rv_tmp=$NY_DIR/.nyyrikki-new
	{ cp -- "$NY_KRL" "$NY_WORK/krl" &&
		ssh-keygen -q -k -u -f "$NY_WORK/krl" "$NY_WORK/revoke.pub" &&
		rm -f -- "$ny_rv_tmp" && cp -- "$NY_WORK/krl" "$ny_rv_tmp" &&
		chown 0:0 "$ny_rv_tmp" && chmod 0644 "$ny_rv_tmp" &&
		mv -f -- "$ny_rv_tmp" "$NY_KRL"; } || die "can't add the revoked CA keys to $NY_KRL"
	say "added the revoked CA keys to $NY_KRL"
}

ny_drop() {
	if [ -e "$1" ] || [ -L "$1" ]; then
		NY_CHANGED=1
		rm -f -- "$1" || die "can't remove $1"
		say "removed $1"
	fi
}

# ny_sshd_verify ACCOUNTS...: sshd -t, then sshd -T for each account and
# source address shows D3's and D4's values.
ny_sshd_verify() {
	ny_sv_t=$("$NY_SSHD_BIN" -t 2>&1) || {
		warn "sshd -t fails: $ny_sv_t"
		return 1
	}
	for ny_sv_a in "$@"; do
		for ny_sv_s in $NY_SOURCES; do
			ny_sv_ip=${ny_sv_s%/*}
			ny_sv_eff=$("$NY_SSHD_BIN" -T -C "user=$ny_sv_a,host=$ny_sv_ip,addr=$ny_sv_ip" 2>&1) || {
				warn "sshd -T -C user=$ny_sv_a,addr=$ny_sv_ip fails: $ny_sv_eff"
				return 1
			}
			ny_sv_want="authenticationmethods publickey
authorizedkeysfile none
authorizedkeyscommand none
authorizedkeyscommanduser nobody
authorizedprincipalscommand none
authorizedprincipalscommanduser nobody
permituserenvironment no
passwordauthentication no
kbdinteractiveauthentication no
hostbasedauthentication no
clientaliveinterval 5
clientalivecountmax 3
trustedusercakeys $NY_CA
authorizedprincipalsfile $NY_PRINC/%u
revokedkeys $NY_KRL"
			if [ "$NY_GSSAPI" = 1 ]; then
				ny_sv_want="$ny_sv_want${NY_NL}gssapiauthentication no"
			fi
			if [ "$NY_CERT_ON" = 1 ]; then
				ny_sv_want="$ny_sv_want${NY_NL}hostcertificate $NY_HOSTCERT"
			fi
			ny_sv_bad=$(printf '%s\n' "$ny_sv_want" | while IFS= read -r ny_sv_w; do
				case "$NY_NL$ny_sv_eff$NY_NL" in
				*"$NY_NL$ny_sv_w$NY_NL"*) ;;
				*) printf '%s; ' "$ny_sv_w" ;;
				esac
			done)
			if [ -n "$ny_sv_bad" ]; then
				warn "for $ny_sv_a from $ny_sv_ip, sshd's effective configuration lacks: $ny_sv_bad(another setting wins over Nyyrikki's)"
				return 1
			fi
		done
	done
	return 0
}

# Step 3: restrict.
ny_restrict() {
	make_dir "$NY_DIR" || die "can't create $NY_DIR"
	# The mark first: from here on, the pull refuses every bundle issued
	# before this script (docs/08 D13). Then the signers, from the data
	# lines, never from a bundle.
	ny_gen_state "$NY_WORK/state" || die "can't write to $NY_WORK"
	put_file "$NY_WORK/state" "$NY_STATE" 0644 || die "can't write $NY_STATE"
	# shellcheck disable=SC2086 # base64 keys
	ny_gen_keys "$NY_WORK/signers" $NY_SIGNER_B64 || die "can't write to $NY_WORK"
	put_file "$NY_WORK/signers" "$NY_SIGNERS" 0644 || die "can't write $NY_SIGNERS"
	ny_gen_ca "$NY_WORK/ca" || die "can't write to $NY_WORK"
	put_file "$NY_WORK/ca" "$NY_CA" 0644 || die "can't write $NY_CA"
	if [ ! -f "$NY_KRL" ]; then
		rm -f -- "$NY_WORK/krl"
		if [ -n "$NY_REVOKED_B64" ]; then
			# shellcheck disable=SC2086 # base64 keys
			ny_gen_keys "$NY_WORK/revoke.pub" $NY_REVOKED_B64 || die "can't write to $NY_WORK"
			ssh-keygen -q -k -f "$NY_WORK/krl" "$NY_WORK/revoke.pub" || die "can't create the key revocation list"
		else
			ssh-keygen -q -k -f "$NY_WORK/krl" || die "can't create an empty key revocation list"
		fi
		put_file "$NY_WORK/krl" "$NY_KRL" 0644 || die "can't write $NY_KRL"
	fi
	ny_match=$NY_ACCOUNTS
	for ny_a in $NY_STALE_EXISTING; do
		ny_match="$ny_match $ny_a"
	done
	# shellcheck disable=SC2086 # account names are slugs
	ny_gen_sshd "$NY_WORK/sshd" $ny_match || die "can't write to $NY_WORK"
	put_file "$NY_WORK/sshd" "$NY_SSHD" 0644 || die "can't write $NY_SSHD"
	# shellcheck disable=SC2086
	ny_sshd_verify $ny_match || die "sshd's configuration with Nyyrikki's drop-in doesn't check out"
	ny_reload_sshd || die "reloading sshd failed"
	say "wrote $NY_STATE, $NY_SIGNERS, $NY_CA, $NY_KRL and $NY_SSHD; sshd reloaded"
}

# Step 4: create.
ny_create() {
	make_dir "$NY_PRINC" || die "can't create $NY_PRINC"
	for ny_a in $NY_ACCOUNTS; do
		if has_word "$NY_CREATE" "$ny_a"; then
			# Checked in step 1; checked again right before acting.
			account_exists "$ny_a" && die "the account $ny_a appeared during the run"
			if [ -e "/home/$ny_a" ] || [ -L "/home/$ny_a" ]; then
				die "/home/$ny_a appeared during the run"
			fi
			if ! has_word "$NY_LISTED" "$ny_a"; then
				NY_LISTED="${NY_LISTED:+$NY_LISTED }$ny_a"
				# shellcheck disable=SC2086
				ny_gen_list "$NY_WORK/list" $NY_LISTED || die "can't write to $NY_WORK"
				put_file "$NY_WORK/list" "$NY_LIST" 0644 || die "can't write $NY_LIST"
			fi
			NY_CHANGED=1
			printf 'A - %s\n' "$ny_a" >>"$NY_WORK/journal" || die "can't write to $NY_WORK"
			useradd -m -d "/home/$ny_a" -s /bin/sh -U -p '*' -c "Nyyrikki account of ${ny_a#ny-}" -- "$ny_a" ||
				die "can't create the account $ny_a"
			ny_why=$(account_check "$ny_a") || die "the account $ny_a isn't as expected after creating it: $ny_why"
			say "created the account $ny_a"
		fi
		ny_gen_principals "$NY_WORK/principals" "${ny_a#ny-}" || die "can't write to $NY_WORK"
		put_file "$NY_WORK/principals" "$NY_PRINC/$ny_a" 0644 || die "can't write $NY_PRINC/$ny_a"
	done
}

# Step 5: remove stale accounts.
ny_remove_stale() {
	for ny_a in $NY_STALE; do
		if account_exists "$ny_a"; then
			has_processes "$ny_a"
			case $? in
			0) die "the account $ny_a of a human no longer on the target has processes; end them ($(ny_end_hint "$ny_a")) and run the setup again. Nyyrikki's sudoers and principals files for it are gone, so Nyyrikki can't log in to it. Running: $(ps -o pid=,args= -u "$ny_a" 2>/dev/null | head -n 5 | tr '\n' ';')" ;;
			1) ;;
			*) die "can't tell whether $ny_a has processes" ;;
			esac
			ny_why=$(account_check "$ny_a") || die "the account $ny_a of a human no longer on the target changed since the setup created it ($ny_why); Nyyrikki's sudoers and principals files for it are gone. Delete it by hand"
			ny_delete_account "$ny_a" || die "can't delete the account $ny_a"
			say "deleted the account $ny_a and /home/$ny_a"
		fi
		ny_rest=
		for ny_l in $NY_LISTED; do
			[ "$ny_l" = "$ny_a" ] || ny_rest="${ny_rest:+$ny_rest }$ny_l"
		done
		NY_LISTED=$ny_rest
		# shellcheck disable=SC2086
		ny_gen_list "$NY_WORK/list" $NY_LISTED || die "can't write to $NY_WORK"
		put_file "$NY_WORK/list" "$NY_LIST" 0644 || die "can't write $NY_LIST"
		# The account is gone: rolling back must not bring back its
		# sudoers or principals file.
		forget_path "$NY_SUDO_PREFIX$ny_a" || die "can't write to $NY_WORK"
		forget_path "$NY_PRINC/$ny_a" || die "can't write to $NY_WORK"
	done
	if [ -n "$NY_STALE_EXISTING" ]; then
		# shellcheck disable=SC2086
		ny_gen_sshd "$NY_WORK/sshd" $NY_ACCOUNTS || die "can't write to $NY_WORK"
		put_file "$NY_WORK/sshd" "$NY_SSHD" 0644 || die "can't write $NY_SSHD"
		# shellcheck disable=SC2086
		ny_sshd_verify $NY_ACCOUNTS || die "sshd's configuration with Nyyrikki's drop-in doesn't check out"
		ny_reload_sshd || die "reloading sshd failed"
	fi
}

# Step 6: grant sudo.
ny_grant() {
	[ "$NY_SUDO" = true ] || return 0
	for ny_a in $NY_ACCOUNTS; do
		ny_gen_sudoers "$NY_WORK/sudoers" "$ny_a" || die "can't write to $NY_WORK"
		chmod 0440 "$NY_WORK/sudoers" || die "can't write to $NY_WORK"
		ny_t=$(visudo -cf "$NY_WORK/sudoers" 2>&1) || die "visudo refuses the sudoers file for $ny_a: $ny_t"
		put_file "$NY_WORK/sudoers" "$NY_SUDO_PREFIX$ny_a" 0440 || die "can't write $NY_SUDO_PREFIX$ny_a"
		say "wrote $NY_SUDO_PREFIX$ny_a"
	done
}

# ny_session_kill_applies: every condition of step 7 holds. Prints the
# first one that doesn't.
ny_session_kill_applies() {
	if [ "$NY_SYSTEMD" != 1 ]; then
		printf 'systemd is not PID 1'
		return 1
	fi
	case "$NY_NL$("$NY_SSHD_BIN" -T 2>/dev/null)$NY_NL" in
	*"${NY_NL}usepam yes$NY_NL"*) ;;
	*)
		printf "sshd doesn't use PAM"
		return 1
		;;
	esac
	if ! ny_pam_reaches_systemd; then
		printf "pam_systemd isn't in sshd's PAM session stack"
		return 1
	fi
	if ! ny_logind_values; then
		printf "can't read logind's KillUserProcesses and KillOnlyUsers"
		return 1
	fi
	if [ "$NY_KUP" = no ] && [ -z "$NY_KOU" ]; then
		:
	elif [ "$NY_KUP" = yes ] && [ "$NY_LOGIND_OURS" = 1 ] && [ -n "$NY_KOU" ]; then
		for ny_u in $NY_KOU; do
			if ! has_word "$NY_LISTED $NY_ACCOUNTS $NY_STALE" "$ny_u"; then
				printf 'logind kills the processes of %s, not a Nyyrikki account' "$ny_u"
				return 1
			fi
		done
	else
		printf 'logind already has KillUserProcesses=%s KillOnlyUsers=%s' "$NY_KUP" "$NY_KOU"
		return 1
	fi
	if ! ny_distro_measured; then
		printf "session kill isn't measured on this distribution yet (docs/07 M18)"
		return 1
	fi
	return 0
}

# Step 7: session kill.
ny_session_kill() {
	if ny_why=$(ny_session_kill_applies); then
		make_dir "$NY_LOGIND_DIR" || die "can't create $NY_LOGIND_DIR"
		make_dir "$NY_SCOPE_DIR" || die "can't create $NY_SCOPE_DIR"
		ny_gen_logind "$NY_WORK/logind" || die "can't write to $NY_WORK"
		ny_gen_scope "$NY_WORK/scope" || die "can't write to $NY_WORK"
		if ! cmp -s "$NY_WORK/logind" "$NY_LOGIND" || ! cmp -s "$NY_WORK/scope" "$NY_SCOPE"; then
			NY_LOGIND_TOUCHED=1
			put_file "$NY_WORK/logind" "$NY_LOGIND" 0644 || die "can't write $NY_LOGIND"
			put_file "$NY_WORK/scope" "$NY_SCOPE" 0644 || die "can't write $NY_SCOPE"
			systemctl daemon-reload || die "systemctl daemon-reload failed"
			ny_restart_logind || die "restarting systemd-logind failed"
		fi
		ny_i=0
		while :; do
			if ny_logind_values && [ "$NY_KUP" = yes ] && [ "$NY_KOU" = "$NY_ACCOUNTS" ]; then
				break
			fi
			ny_i=$((ny_i + 1))
			[ "$ny_i" -lt 10 ] || die "logind doesn't report KillUserProcesses=yes and KillOnlyUsers=$NY_ACCOUNTS after the restart"
			sleep 1
		done
		NY_SESSION_KILL=true
		say "session kill: logind stops the session scopes of $NY_ACCOUNTS when the connection closes"
	else
		say "session kill: no: $ny_why"
		if [ -e "$NY_LOGIND" ] || [ -e "$NY_SCOPE" ]; then
			NY_LOGIND_TOUCHED=1
			remove_file "$NY_LOGIND" || die "can't remove $NY_LOGIND"
			remove_file "$NY_SCOPE" || die "can't remove $NY_SCOPE"
			if [ "$NY_SYSTEMD" = 1 ]; then
				systemctl daemon-reload || die "systemctl daemon-reload failed"
				ny_restart_logind || die "restarting systemd-logind failed"
			fi
			say "removed Nyyrikki's logind and session scope drop-ins"
		fi
	fi
}

# Step 8: the trust pull (docs/08 D5): pull.sh from this body, pull.conf,
# the CA file of --cacert, and a schedule where a cron runs it. The
# schedule goes last, so a pull never runs with half of its files.
ny_install_pull() {
	ny_gen_pull "$NY_WORK/pull.sh" || die "can't write to $NY_WORK"
	put_file "$NY_WORK/pull.sh" "$NY_PULL" 0755 || die "can't write $NY_PULL"
	if [ "$NY_CACERT_SET" = 1 ]; then
		put_file "$NY_CACERT" "$NY_SERVERCA" 0644 || die "can't write $NY_SERVERCA"
	elif [ -e "$NY_SERVERCA" ]; then
		remove_file "$NY_SERVERCA" || die "can't remove $NY_SERVERCA"
		warn "removed $NY_SERVERCA, since this run has no --cacert; if Nyyrikki's certificate comes from a private CA, run the setup again with --cacert, or the pull fails"
	fi
	ny_gen_pullconf "$NY_WORK/pull.conf" || die "can't write to $NY_WORK"
	put_file "$NY_WORK/pull.conf" "$NY_PULLCONF" 0644 || die "can't write $NY_PULLCONF"
	case $NY_SCHED in
	cron.d)
		remove_file "$NY_PERIODIC" || die "can't remove $NY_PERIODIC"
		ny_gen_cron "$NY_WORK/cron" || die "can't write to $NY_WORK"
		put_file "$NY_WORK/cron" "$NY_CRON" 0644 || die "can't write $NY_CRON"
		;;
	periodic)
		remove_file "$NY_CRON" || die "can't remove $NY_CRON"
		ny_gen_periodic "$NY_WORK/periodic" || die "can't write to $NY_WORK"
		put_file "$NY_WORK/periodic" "$NY_PERIODIC" 0755 || die "can't write $NY_PERIODIC"
		;;
	*)
		remove_file "$NY_CRON" || die "can't remove $NY_CRON"
		remove_file "$NY_PERIODIC" || die "can't remove $NY_PERIODIC"
		;;
	esac
	say "wrote $NY_PULL and $NY_PULLCONF"
}

# Step 9: what the setup did, and what goes into the target's registry
# entry if the host isn't enrolled.
ny_report() {
	say ""
	case $NY_SCHED in
	cron.d) say "pull: cron.d ($NY_CRON runs $NY_PULL every 15 minutes)" ;;
	periodic) say "pull: periodic ($NY_PERIODIC runs $NY_PULL every 15 minutes)" ;;
	*) say "pull: none ($NY_SCHED_WHY; run $NY_PULL by hand, or the setup again, to take up rotations and revocations)" ;;
	esac
	say ""
	if [ "$NY_ENROLL_SET" = 1 ]; then
		say "Done; enrolling next. Without enrollment, this would go into target $NY_TARGET's ssh block:"
	else
		say "Done. Enroll the host (nyyrikkid enroll-token $NY_TARGET, then this command with --enroll), or put this into target $NY_TARGET's ssh block in Nyyrikki's values, and roll out:"
	fi
	say ""
	say "      host_keys:"
	ny_fps=
	for ny_f in /etc/ssh/ssh_host_*_key.pub; do
		[ -f "$ny_f" ] || continue
		IFS=' ' read -r ny_type ny_key ny_rest <"$ny_f" || continue
		case $ny_type in
		ssh-* | ecdsa-*) ;;
		*) continue ;;
		esac
		is_b64 "$ny_key" || continue
		say "        - $ny_type $ny_key"
		ny_fp=$(ssh-keygen -l -f "$ny_f" 2>/dev/null) || ny_fp="(no fingerprint) $ny_f"
		ny_fps="$ny_fps$NY_NL    $ny_fp"
	done
	say "      sudo: $NY_SUDO"
	say "      session_kill: $NY_SESSION_KILL"
	say ""
	say "Host key fingerprints, to compare:$ny_fps"
}

# --- step 10: enrollment (docs/08 D7) ---------------------------------------
#
# After steps 2 to 9 have succeeded and nothing is to be rolled back: a
# failed enrollment leaves the host set up, refused by Nyyrikki until it
# is enrolled or pinned (fail closed), and removes only a certificate this
# run installed that sshd didn't take.

# ny_put_now SRC DEST MODE: installs SRC as DEST atomically, outside the
# journal (nothing is rolled back in step 10).
ny_put_now() {
	ny_pn_tmp=${2%/*}/.nyyrikki-new
	rm -f -- "$ny_pn_tmp" &&
		cp -- "$1" "$ny_pn_tmp" &&
		chown 0:0 "$ny_pn_tmp" &&
		chmod "$3" "$ny_pn_tmp" &&
		mv -f -- "$ny_pn_tmp" "$2"
}

# ny_enroll_abort ends a failed enrollment. Never returns.
ny_enroll_abort() {
	trap '' INT TERM HUP PIPE
	trap - EXIT
	NY_ENROLLING=0
	if [ "$NY_CERT_PENDING" = 1 ]; then
		NY_CERT_PENDING=0
		if [ "$NY_CERT_PREV" = 1 ] && ny_put_now "$NY_WORK/prev-cert.pub" "$NY_HOSTCERT" 0644; then
			# The host was enrolled before this run: put its working
			# certificate back rather than leave it unenrolled.
			warn "restoring the earlier host certificate in place of the one this run installed"
		else
			NY_CERT_ON=0
			[ "$NY_CERT_PREV" = 0 ] || warn "can't put the earlier host certificate back: the host is no longer enrolled"
			warn "removing the host certificate this run installed, and its HostCertificate line"
			rm -f -- "$NY_HOSTCERT" || warn "can't remove $NY_HOSTCERT"
		fi
		# shellcheck disable=SC2086 # account names are slugs
		if ny_gen_sshd "$NY_WORK/sshd" $NY_ACCOUNTS && ny_put_now "$NY_WORK/sshd" "$NY_SSHD" 0644; then
			if "$NY_SSHD_BIN" -t; then
				ny_reload_sshd || warn "reloading sshd failed"
			else
				warn "sshd -t fails after undoing the certificate change too; sshd was not reloaded"
			fi
		else
			warn "can't rewrite $NY_SSHD without HostCertificate"
		fi
	fi
	if [ "$NY_CERT_ON" = 1 ]; then
		warn "The enrollment failed. The host is set up (steps 1 to 9) and keeps its earlier certificate. To enroll it again, run the setup with a new token (nyyrikkid enroll-token $NY_TARGET)."
	else
		warn "The enrollment failed. The host is set up (steps 1 to 9), and Nyyrikki refuses it until it is enrolled or its keys are pinned. Run the setup again with a new token (nyyrikkid enroll-token $NY_TARGET)."
	fi
	ny_cleanup
	exit 1
}

# ny_post URL BODYFILE OUT MAXTIME: POSTs BODYFILE with the token, prints
# the HTTP status. The token goes in a header file, so no process listing
# shows it.
ny_post() {
	set -- curl -sS --proto =https --max-time "$4" -o "$3" -w '%{http_code}' \
		-H @"$NY_WORK/auth" -H 'Content-Type: text/plain; charset=utf-8' --data-binary @"$2" "$1"
	if [ "$NY_CACERT_SET" = 1 ]; then
		set -- "$@" --cacert "$NY_SERVERCA"
	fi
	"$@" 2>"$NY_WORK/curl.err"
}

# ny_answer FILE: the server's refusal, one line, printable, for messages.
ny_answer() {
	head -c 300 "$1" 2>/dev/null | head -n 1 | tr -c ' -~' ' '
}

ny_enroll() {
	umask 077
	printf 'Authorization: Nyyrikki-Enroll %s\n' "$NY_ENROLL" >"$NY_WORK/auth" || die "can't write to $NY_WORK"
	umask 022
	# shellcheck disable=SC2034 # the comment
	IFS=' ' read -r ny_en_type ny_en_key ny_en_rest <"$NY_HOSTKEY.pub" || die "can't read $NY_HOSTKEY.pub"
	[ "$ny_en_type" = ssh-ed25519 ] && is_b64 "$ny_en_key" || die "$NY_HOSTKEY.pub isn't an ssh-ed25519 key"
	printf 'ssh-ed25519 %s\n' "$ny_en_key" >"$NY_WORK/hostkey.pub" || die "can't write to $NY_WORK"
	ny_en_fp=$(ssh-keygen -l -f "$NY_WORK/hostkey.pub" 2>/dev/null) || die "$NY_HOSTKEY.pub doesn't parse"
	case $ny_en_fp in
	*'(ED25519)') ;;
	*) die "$NY_HOSTKEY.pub isn't an ed25519 key" ;;
	esac
	ny_en_fp=${ny_en_fp#* }
	ny_en_fp=${ny_en_fp%% *}
	printf 'HOST_KEY=ssh-ed25519 %s\nSESSION_KILL=%s\nEND=2\n' "$ny_en_key" "$NY_SESSION_KILL" >"$NY_WORK/enroll" || die "can't write to $NY_WORK"
	say ""
	say "Enrolling with $NY_URL. This host's key:"
	say ""
	say "    ED25519 $ny_en_fp"
	say ""
	say "Approve on Telegram only if the message shows this same fingerprint. Waiting for the approval..."
	ny_en_code=$(ny_post "$NY_URL/hosts/$NY_TARGET/enroll" "$NY_WORK/enroll" "$NY_WORK/answer" 900) ||
		die "enrollment: no answer from $NY_URL: $(ny_answer "$NY_WORK/curl.err")"
	[ "$ny_en_code" = 200 ] || die "enrollment refused (HTTP $(ny_show "$ny_en_code")): $(ny_answer "$NY_WORK/answer")"

	# The answer: exactly HOST_CERT and END=1 (docs/08 §10 SE5).
	ny_en_cert=
	ny_en_n=0
	ny_en_end=0
	while IFS= read -r ny_en_l; do
		[ "$ny_en_end" = 0 ] || die "enrollment: a line after END in the answer"
		case $ny_en_l in
		'HOST_CERT=ssh-ed25519-cert-v01@openssh.com '*)
			[ -z "$ny_en_cert" ] || die "enrollment: two certificates in the answer"
			ny_en_cert=${ny_en_l#HOST_CERT=ssh-ed25519-cert-v01@openssh.com }
			is_b64 "$ny_en_cert" || die "enrollment: the certificate isn't base64"
			;;
		END=1)
			[ "$ny_en_n" = 1 ] || die "enrollment: the answer is cut off"
			ny_en_end=1
			continue
			;;
		*) die "enrollment: an unexpected line in the answer: $(ny_show "$ny_en_l")" ;;
		esac
		ny_en_n=$((ny_en_n + 1))
	done <"$NY_WORK/answer"
	[ "$ny_en_end" = 1 ] && [ -n "$ny_en_cert" ] || die "enrollment: the answer is cut off"
	printf 'ssh-ed25519-cert-v01@openssh.com %s\n' "$ny_en_cert" >"$NY_WORK/cert.pub" || die "can't write to $NY_WORK"
	# A host certificate for this host's own key (docs/08 D8).
	ny_en_l=$(ssh-keygen -L -f "$NY_WORK/cert.pub" 2>&1) || die "enrollment: the certificate doesn't parse: $(ny_show "$ny_en_l")"
	case $ny_en_l in
	*"Type: ssh-ed25519-cert-v01@openssh.com host certificate"*) ;;
	*) die "enrollment: the answer isn't a host certificate" ;;
	esac
	case "$ny_en_l$NY_NL" in
	*"Public key: ED25519-CERT $ny_en_fp$NY_NL"*) ;;
	*) die "enrollment: the certificate isn't for this host's key" ;;
	esac

	# Install it, then the drop-in that names it, and check them with sshd.
	# A re-enrollment keeps the earlier certificate to put back if this
	# one fails (round 1 of #50).
	if [ -f "$NY_HOSTCERT" ]; then
		cp -- "$NY_HOSTCERT" "$NY_WORK/prev-cert.pub" || die "can't keep a copy of $NY_HOSTCERT"
		NY_CERT_PREV=1
	fi
	NY_CERT_PENDING=1
	ny_put_now "$NY_WORK/cert.pub" "$NY_HOSTCERT" 0644 || die "can't write $NY_HOSTCERT"
	NY_CERT_ON=1
	# shellcheck disable=SC2086 # account names are slugs
	ny_gen_sshd "$NY_WORK/sshd" $NY_ACCOUNTS || die "can't write to $NY_WORK"
	ny_put_now "$NY_WORK/sshd" "$NY_SSHD" 0644 || die "can't write $NY_SSHD"
	# shellcheck disable=SC2086
	ny_sshd_verify $NY_ACCOUNTS || die "sshd doesn't accept its configuration with the host certificate"
	ny_reload_sshd || die "reloading sshd failed"
	NY_CERT_PENDING=0
	say "installed $NY_HOSTCERT and named it in $NY_SSHD; sshd reloaded"

	# Nyyrikki checks it can log in to each account (docs/08 D7 step 4).
	say "Nyyrikki now checks that it can log in to each account..."
	: >"$NY_WORK/empty" || die "can't write to $NY_WORK"
	ny_en_code=$(ny_post "$NY_URL/hosts/$NY_TARGET/enroll/check" "$NY_WORK/empty" "$NY_WORK/answer" 300) ||
		ny_en_code=000
	ny_en_bad=0
	if [ "$ny_en_code" = 200 ]; then
		ny_en_n=0
		ny_en_end=0
		while IFS= read -r ny_en_l; do
			[ "$ny_en_end" = 0 ] || { ny_en_bad=1; break; }
			case $ny_en_l in
			OK=ny-* | REFUSED=ny-* | NOT_CHECKED=ny-*)
				ny_en_a=${ny_en_l#*=}
				is_slug "${ny_en_a#ny-}" 29 || { ny_en_bad=1; break; }
				case $ny_en_l in
				OK=*) say "check: $ny_en_a: ok" ;;
				REFUSED=*) say "check: $ny_en_a: refused"; ny_en_bad=1 ;;
				*) say "check: $ny_en_a: not checked"; ny_en_bad=1 ;;
				esac
				;;
			HINT=*) say "hint: $(printf '%.600s' "${ny_en_l#HINT=}" | tr -c ' -~' '?')" ;;
			END=*)
				[ "${ny_en_l#END=}" = "$ny_en_n" ] || ny_en_bad=1
				ny_en_end=1
				continue
				;;
			*) ny_en_bad=1; break ;;
			esac
			ny_en_n=$((ny_en_n + 1))
		done <"$NY_WORK/answer"
		[ "$ny_en_end" = 1 ] || ny_en_bad=1
	else
		ny_en_bad=1
		warn "the check after enrollment failed (HTTP $(ny_show "$ny_en_code")): $(ny_answer "$NY_WORK/answer") $(ny_answer "$NY_WORK/curl.err")"
	fi
	trap - EXIT
	trap '' INT TERM HUP PIPE
	NY_ENROLLING=0
	if [ "$ny_en_bad" = 1 ]; then
		warn "Enrolled: Nyyrikki trusts this host's certificate. But it couldn't log in to every account, so runs on them fail; fix what the hint names, then enroll again with a new token to check."
		ny_cleanup
		exit 1
	fi
	say "Enrolled: Nyyrikki trusts this host by its certificate, and can log in to every account."
	ny_cleanup
	exit 0
}

# --- --status --------------------------------------------------------------------

# ny_status_keys LABEL FILE: the fingerprints of the keys in FILE.
ny_status_keys() {
	if [ ! -f "$2" ]; then
		say "$1: none ($2 doesn't exist)"
		return 0
	fi
	say "$1:"
	while IFS= read -r ny_sk_l; do
		printf '%s\n' "$ny_sk_l" >"$NY_WORK/s.pub" 2>/dev/null || continue
		ny_sk_fp=$(ssh-keygen -l -f "$NY_WORK/s.pub" 2>/dev/null) || ny_sk_fp="(doesn't parse)"
		if [ -f "$NY_KRL" ]; then
			ssh-keygen -Q -f "$NY_KRL" "$NY_WORK/s.pub" >/dev/null 2>&1
			case $? in
			0) ;;
			1) ny_sk_fp="$ny_sk_fp  REVOKED by $NY_KRL" ;;
			*) ny_sk_fp="$ny_sk_fp  (can't check against $NY_KRL)" ;;
			esac
		fi
		say "    $ny_sk_fp"
	done <"$2"
}

# ny_status prints what is installed, the pull's schedule and its last
# bundle, and changes nothing (docs/08 D13).
ny_status() {
	say "Nyyrikki host setup status; this script is for target $NY_TARGET"
	if [ ! -d "$NY_DIR" ]; then
		say "installed: no ($NY_DIR doesn't exist)"
		ny_cleanup
		exit 0
	fi
	if [ -f "$NY_SSHD" ]; then
		say "installed: yes ($NY_SSHD)"
	else
		say "installed: partly; $NY_SSHD is missing (run the setup again)"
	fi
	if [ -f "$NY_LIST" ]; then
		say "accounts: $(tr '\n' ' ' <"$NY_LIST")"
	fi
	ny_status_keys "trusted user CA keys ($NY_CA)" "$NY_CA"
	ny_status_keys "bundle signers ($NY_SIGNERS)" "$NY_SIGNERS"
	# This script's own keys, against the host's revocation list (round 1
	# of #50): a run would refuse them.
	if [ -f "$NY_KRL" ]; then
		for ny_sk_k in $NY_CA_B64 $NY_SIGNER_B64; do
			printf 'ssh-ed25519 %s\n' "$ny_sk_k" >"$NY_WORK/s.pub" 2>/dev/null || continue
			ssh-keygen -Q -f "$NY_KRL" "$NY_WORK/s.pub" >/dev/null 2>&1
			case $? in
			0) ;;
			1) say "this script trusts $(ssh-keygen -l -f "$NY_WORK/s.pub" 2>/dev/null | cut -d' ' -f2), which $NY_KRL lists: REVOKED; a setup run refuses it" ;;
			*) say "can't check this script's keys against $NY_KRL" ;;
			esac
		done
	fi
	if [ -f "$NY_CRON" ]; then
		say "pull: cron.d ($NY_CRON)"
	elif [ -f "$NY_PERIODIC" ]; then
		say "pull: periodic ($NY_PERIODIC)"
	else
		say "pull: none (no schedule installed; $NY_PULL runs by hand)"
	fi
	if [ -f "$NY_PULLCONF" ]; then
		say "pull from: $(sed -n 's/^URL=//p' "$NY_PULLCONF" | head -n 1 | tr -c ' -~\n' '?')$([ -f "$NY_SERVERCA" ] && printf ', trusting %s' "$NY_SERVERCA")"
		ny_st_t=$(sed -n 's/^TARGET=//p' "$NY_PULLCONF" | head -n 1 | tr -c ' -~\n' '?')
		if [ "$ny_st_t" = "$NY_TARGET" ]; then
			say "pull target: $ny_st_t"
		else
			say "pull target: $ny_st_t, NOT this script's target $NY_TARGET: the host was set up for another target"
		fi
	fi
	if [ -f "$NY_STATE" ] && ny_read_state "$NY_STATE"; then
		ny_clock
		ny_st_when="issued $(ny_date "$((NY_MARK / 1000))")"
		if [ "$NY_MARK_BY" = pull ]; then
			say "last bundle applied: $ny_st_when, by the pull at $(ny_date "${NY_MARK_AT:-0}")"
		else
			say "last bundle applied: none since the setup, whose script was $ny_st_when"
		fi
		if [ "$NY_MARK" -gt "$NY_LIMIT_MS" ]; then
			say "warning: that is more than 10 minutes ahead of this host's clock; check the clock (NTP)"
		fi
	elif [ -e "$NY_STATE" ]; then
		say "last bundle applied: $NY_STATE is malformed (run the setup with --reset-pull-state)"
	else
		say "last bundle applied: none ($NY_STATE doesn't exist)"
	fi
	if [ -f "$NY_HOSTCERT" ]; then
		ny_st_c=$(ssh-keygen -L -f "$NY_HOSTCERT" 2>/dev/null | sed -n -e 's/^[[:space:]]*\(Key ID:\)/\1/p' -e 's/^[[:space:]]*\(Valid:\)/\1/p' -e 's/^[[:space:]]*\(Signing CA:\)/\1/p' | tr -c ' -~\n' '?')
		say "host certificate: $NY_HOSTCERT"
		printf '%s\n' "$ny_st_c" | while IFS= read -r ny_st_l; do say "    $ny_st_l"; done
	else
		say "host certificate: none (not enrolled)"
	fi
	ny_cleanup
	exit 0
}

# --- --uninstall ---------------------------------------------------------------

ny_uninstall() {
	[ "$(id -u)" = 0 ] || die "refused: run as root"
	[ "$NY_DRY" = 1 ] || ny_lock
	NY_SSHD_BIN=$(command -v sshd) || die "refused: sshd not found"
	[ -d /run/systemd/system ] && NY_SYSTEMD=1
	if [ -f "$NY_LIST" ]; then
		while IFS= read -r ny_a; do
			case $ny_a in
			ny-*) is_slug "${ny_a#ny-}" 29 || die "refused: $NY_LIST holds a line that isn't a Nyyrikki account" ;;
			*) die "refused: $NY_LIST holds a line that isn't a Nyyrikki account" ;;
			esac
			has_word "$NY_LISTED" "$ny_a" || NY_LISTED="${NY_LISTED:+$NY_LISTED }$ny_a"
		done <"$NY_LIST"
	fi
	if [ "$NY_DRY" = 1 ]; then
		say "would remove: $NY_CRON, $NY_PERIODIC, /etc/sudoers.d/50-nyyrikki-*, $NY_PRINC, the accounts ${NY_LISTED:-(none)} and their homes, $NY_LOGIND, $NY_SCOPE, $NY_SSHD (with its HostCertificate line), $NY_DIR (with the trust pull, its state and the host certificate)"
		for ny_a in $NY_LISTED; do
			has_processes "$ny_a" && say "would refuse: $ny_a has processes"
		done
		ny_cleanup
		exit 0
	fi
	# sshd must accept its configuration before anything changes: a failed
	# check after the drop-in is gone would leave sshd unreloaded.
	ny_t=$("$NY_SSHD_BIN" -t 2>&1) || die "refused: sshd -t fails before any change; fix sshd's configuration first: $ny_t"
	# The pull's schedule first, so that no pull starts while the rest goes.
	for ny_f in "$NY_CRON" "$NY_PERIODIC"; do
		if [ -e "$ny_f" ] || [ -L "$ny_f" ]; then
			rm -f -- "$ny_f" || die "can't remove $ny_f"
			say "removed $ny_f"
		fi
	done
	rm -f -- "${NY_CRON%/*}/.nyyrikki-new" "${NY_PERIODIC%/*}/.nyyrikki-new" 2>/dev/null
	for ny_f in "$NY_SUDO_PREFIX"*; do
		[ -e "$ny_f" ] || [ -L "$ny_f" ] || continue
		rm -f -- "$ny_f" || die "can't remove $ny_f"
		say "removed $ny_f"
	done
	if [ -d "$NY_PRINC" ]; then
		rm -rf -- "$NY_PRINC" || die "can't remove $NY_PRINC"
		say "removed $NY_PRINC"
	fi
	for ny_a in $NY_LISTED; do
		account_exists "$ny_a" || continue
		has_processes "$ny_a"
		case $? in
		0) die "the account $ny_a has processes; end them first ($(ny_end_hint "$ny_a")), then run --uninstall again. Nyyrikki's sudoers and principals files are gone, so Nyyrikki can't log in to it. Running: $(ps -o pid=,args= -u "$ny_a" 2>/dev/null | head -n 5 | tr '\n' ';')" ;;
		1) ;;
		*) die "can't tell whether $ny_a has processes" ;;
		esac
	done
	for ny_a in $NY_LISTED; do
		if account_exists "$ny_a"; then
			ny_delete_account "$ny_a" || die "can't delete the account $ny_a"
			say "deleted the account $ny_a and /home/$ny_a"
		elif [ -e "/home/$ny_a" ] || [ -L "/home/$ny_a" ]; then
			warn "left /home/$ny_a in place: its account doesn't exist"
		fi
	done
	ny_lg=0
	for ny_f in "$NY_LOGIND" "$NY_SCOPE"; do
		if [ -e "$ny_f" ] || [ -L "$ny_f" ]; then
			rm -f -- "$ny_f" || die "can't remove $ny_f"
			ny_lg=1
			say "removed $ny_f"
		fi
	done
	rm -f -- "$NY_LOGIND_DIR/.nyyrikki-new" "$NY_SCOPE_DIR/.nyyrikki-new" 2>/dev/null
	# The directories, if empty: the setup created them.
	rmdir -- "$NY_SCOPE_DIR" "$NY_LOGIND_DIR" 2>/dev/null
	if [ "$ny_lg" = 1 ] && [ "$NY_SYSTEMD" = 1 ]; then
		systemctl daemon-reload || die "systemctl daemon-reload failed"
		ny_restart_logind || die "restarting systemd-logind failed"
	fi
	rm -f -- "$NY_SSHD" "$NY_SSHD_DIR/.nyyrikki-new" /etc/sudoers.d/.nyyrikki-new || die "can't remove $NY_SSHD"
	say "removed $NY_SSHD"
	# $NY_DIR goes only once sshd runs without the drop-in: until then it
	# reads RevokedKeys from there, and refuses every key login without it.
	ny_t=$("$NY_SSHD_BIN" -t 2>&1) || die "sshd -t fails after removing Nyyrikki's drop-in: $ny_t. $NY_DIR is kept, since the running sshd still reads it; fix sshd's configuration, then run --uninstall again"
	ny_reload_sshd || die "reloading sshd failed; $NY_DIR is kept, since the running sshd still reads it"
	rm -rf -- "$NY_DIR" || die "can't remove $NY_DIR"
	say "removed $NY_DIR, with the trust pull, its state and the host certificate"
	say "Nyyrikki's setup is removed; sshd reloaded."
	ny_cleanup
	exit 0
}

# --- --dry-run -------------------------------------------------------------------

ny_dry_run() {
	ny_match=$NY_ACCOUNTS
	for ny_a in $NY_STALE_EXISTING; do
		ny_match="$ny_match $ny_a"
	done
	for ny_a in $NY_STALE; do
		say "would remove ${NY_SUDO_PREFIX}$ny_a and $NY_PRINC/$ny_a, if present"
	done
	if [ "$NY_SUDO" = false ]; then
		for ny_a in $NY_ACCOUNTS; do
			say "would remove ${NY_SUDO_PREFIX}$ny_a, if present (SUDO=false)"
		done
	fi
	for ny_k in $NY_REVOKED_B64; do
		[ -f "$NY_KRL" ] || break
		printf 'ssh-ed25519 %s\n' "$ny_k" >"$NY_WORK/q.pub" || die "can't write to $NY_WORK"
		if ssh-keygen -Q -f "$NY_KRL" "$NY_WORK/q.pub" >/dev/null 2>&1; then
			say "would add to $NY_KRL: $(ssh-keygen -l -f "$NY_WORK/q.pub" 2>/dev/null)"
		fi
	done
	ny_gen_state "$NY_WORK/state" || die "can't write to $NY_WORK"
	ny_print_file "$NY_STATE" 0644 "$NY_WORK/state"
	# shellcheck disable=SC2086 # base64 keys
	ny_gen_keys "$NY_WORK/signers" $NY_SIGNER_B64 || die "can't write to $NY_WORK"
	ny_print_file "$NY_SIGNERS" 0644 "$NY_WORK/signers"
	ny_gen_ca "$NY_WORK/ca" || die "can't write to $NY_WORK"
	ny_print_file "$NY_CA" 0644 "$NY_WORK/ca"
	if [ ! -f "$NY_KRL" ]; then
		say "would write $NY_KRL (mode 0644): a key revocation list (ssh-keygen -k)${NY_REVOKED_B64:+ of the REVOKED_CA_KEYs}"
	fi
	# shellcheck disable=SC2086
	ny_gen_sshd "$NY_WORK/sshd" $ny_match || die "can't write to $NY_WORK"
	ny_print_file "$NY_SSHD" 0644 "$NY_WORK/sshd"
	for ny_a in $NY_CREATE; do
		say "would create the account $ny_a: home /home/$ny_a, shell /bin/sh, password field '*'"
	done
	for ny_h in $NY_HUMANS; do
		ny_gen_principals "$NY_WORK/principals" "$ny_h" || die "can't write to $NY_WORK"
		ny_print_file "$NY_PRINC/ny-$ny_h" 0644 "$NY_WORK/principals"
	done
	ny_l=$NY_LISTED
	for ny_a in $NY_ACCOUNTS; do
		has_word "$ny_l" "$ny_a" || ny_l="${ny_l:+$ny_l }$ny_a"
	done
	ny_r=
	for ny_a in $ny_l; do
		has_word "$NY_STALE" "$ny_a" || ny_r="${ny_r:+$ny_r }$ny_a"
	done
	# shellcheck disable=SC2086
	ny_gen_list "$NY_WORK/list" $ny_r || die "can't write to $NY_WORK"
	ny_print_file "$NY_LIST" 0644 "$NY_WORK/list"
	for ny_a in $NY_STALE_EXISTING; do
		say "would delete the account $ny_a and /home/$ny_a"
	done
	if [ "$NY_SUDO" = true ]; then
		for ny_a in $NY_ACCOUNTS; do
			ny_gen_sudoers "$NY_WORK/sudoers" "$ny_a" || die "can't write to $NY_WORK"
			ny_print_file "$NY_SUDO_PREFIX$ny_a" 0440 "$NY_WORK/sudoers"
		done
	fi
	if ny_why=$(ny_session_kill_applies); then
		ny_gen_logind "$NY_WORK/logind" || die "can't write to $NY_WORK"
		ny_gen_scope "$NY_WORK/scope" || die "can't write to $NY_WORK"
		ny_print_file "$NY_LOGIND" 0644 "$NY_WORK/logind"
		ny_print_file "$NY_SCOPE" 0644 "$NY_WORK/scope"
		say "would restart systemd-logind; session_kill would be true"
	else
		say "session kill: no: $ny_why"
		if [ -e "$NY_LOGIND" ] || [ -e "$NY_SCOPE" ]; then
			say "would remove $NY_LOGIND and $NY_SCOPE"
		fi
		say "session_kill would be false"
	fi
	ny_gen_pull "$NY_WORK/pull.sh" || die "can't write to $NY_WORK"
	say "would write $NY_PULL (mode 0755): the trust pull, $(wc -l <"$NY_WORK/pull.sh") lines of this script's body"
	if [ "$NY_CACERT_SET" = 1 ]; then
		say "would write $NY_SERVERCA (mode 0644): a copy of $(ny_show "$NY_CACERT")"
	elif [ -e "$NY_SERVERCA" ]; then
		say "would remove $NY_SERVERCA: no --cacert"
	fi
	ny_gen_pullconf "$NY_WORK/pull.conf" || die "can't write to $NY_WORK"
	ny_print_file "$NY_PULLCONF" 0644 "$NY_WORK/pull.conf"
	case $NY_SCHED in
	cron.d)
		ny_gen_cron "$NY_WORK/cron" || die "can't write to $NY_WORK"
		ny_print_file "$NY_CRON" 0644 "$NY_WORK/cron"
		;;
	periodic)
		ny_gen_periodic "$NY_WORK/periodic" || die "can't write to $NY_WORK"
		ny_print_file "$NY_PERIODIC" 0755 "$NY_WORK/periodic"
		;;
	esac
	say "pull would be: $NY_SCHED${NY_SCHED_WHY:+ ($NY_SCHED_WHY)}"
	say "dry run: nothing was changed"
	ny_cleanup
	exit 0
}

# --- main ----------------------------------------------------------------------

# ny_args: the options. Each at most once, and only in combinations that
# mean one thing.
ny_args() {
	while [ "$#" -gt 0 ]; do
		case $1 in
		--dry-run)
			[ "$NY_DRY" = 0 ] || die "refused: --dry-run given twice"
			NY_DRY=1
			;;
		--uninstall)
			[ "$NY_UNINSTALL" = 0 ] || die "refused: --uninstall given twice"
			NY_UNINSTALL=1
			;;
		--status)
			[ "$NY_STATUS" = 0 ] || die "refused: --status given twice"
			NY_STATUS=1
			;;
		--reset-pull-state)
			[ "$NY_RESET" = 0 ] || die "refused: --reset-pull-state given twice"
			NY_RESET=1
			;;
		--cacert)
			[ "$NY_CACERT_SET" = 0 ] || die "refused: --cacert given twice"
			[ "$#" -ge 2 ] && [ -n "$2" ] || die "refused: --cacert needs a file"
			NY_CACERT=$2
			NY_CACERT_SET=1
			shift
			;;
		--enroll)
			[ "$NY_ENROLL_SET" = 0 ] || die "refused: --enroll given twice"
			[ "$#" -ge 2 ] || die "refused: --enroll needs a token (nyyrikkid enroll-token)"
			is_token "$2" || die "refused: --enroll: not an enrollment token: $(ny_show "$2")"
			NY_ENROLL=$2
			NY_ENROLL_SET=1
			shift
			;;
		*) die "refused: unknown argument $(ny_show "$1"); only --dry-run, --uninstall, --status, --reset-pull-state, --cacert FILE and --enroll TOKEN" ;;
		esac
		shift
	done
	if [ "$NY_STATUS" = 1 ] && [ "$NY_DRY$NY_UNINSTALL$NY_RESET$NY_CACERT_SET$NY_ENROLL_SET" != 00000 ]; then
		die "refused: --status takes no other option"
	fi
	if [ "$NY_UNINSTALL" = 1 ] && [ "$NY_RESET$NY_CACERT_SET$NY_ENROLL_SET" != 000 ]; then
		die "refused: --uninstall takes only --dry-run"
	fi
	if [ "$NY_DRY" = 1 ] && [ "$NY_ENROLL_SET" = 1 ]; then
		die "refused: --dry-run with --enroll; run the dry run without the token, then enroll"
	fi
}

main() {
	ny_init
	set -u
	trap 'ny_on_signal INT' INT
	trap 'ny_on_signal TERM' TERM
	trap 'ny_on_signal HUP' HUP
	trap 'ny_on_signal PIPE' PIPE
	trap 'ny_on_exit' EXIT
	ny_args "$@"
	if [ -t 0 ]; then
		die "refused: the data lines come from a terminal: the file is cut off after its main line"
	fi
	ny_read_values
	exec </dev/null
	if [ "$NY_STATUS" = 0 ]; then
		say "Nyyrikki host setup for target $NY_TARGET"
	fi

	NY_WORK=$(mktemp -d "${TMPDIR:-/tmp}/nyyrikki-setup.XXXXXX") || die "can't create a work directory"
	chmod 0700 "$NY_WORK" || die "can't create a work directory"
	: >"$NY_WORK/journal" || die "can't write to $NY_WORK"
	: >"$NY_WORK/saved" || die "can't write to $NY_WORK"

	if [ "$NY_STATUS" = 1 ]; then
		ny_status
	fi
	if [ "$NY_UNINSTALL" = 1 ]; then
		ny_uninstall
	fi
	ny_check
	if [ "$NY_DRY" = 1 ]; then
		ny_dry_run
	fi
	ny_take_away
	ny_restrict
	ny_create
	ny_remove_stale
	ny_grant
	ny_session_kill
	ny_install_pull
	trap - EXIT
	trap '' INT TERM HUP PIPE
	NY_CHANGED=0
	ny_report
	if [ "$NY_ENROLL_SET" = 1 ]; then
		NY_ENROLLING=1
		trap 'ny_on_signal INT' INT
		trap 'ny_on_signal TERM' TERM
		trap 'ny_on_signal HUP' HUP
		trap 'ny_on_signal PIPE' PIPE
		trap 'ny_on_exit' EXIT
		ny_enroll
	fi
	ny_cleanup
	exit 0
}

main "$@" <<'NYYRIKKI_VALUES_END'
