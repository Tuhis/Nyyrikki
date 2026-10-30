#!/bin/sh
# Nyyrikki host setup: prepares a Linux host with OpenSSH >= 9.0 as an SSH
# target of Nyyrikki (docs/07-ssh-target.md, section 5.7; D3, D4, D7, D11,
# D15, D16). The manual steps it automates are docs/setup/ssh-hosts.md.
#
# Nyyrikki serves this file at /hosts/<target>/setup.sh with data lines
# (NAME=value) and a terminator after the last line. The data lines are a
# quoted here-document that main reads as text and checks in full before
# it changes anything; they are never executed. main never returns: every
# path ends in exit, so nothing after the terminator runs.
#
#   sh setup.sh               set the host up, or bring it up to date
#   sh setup.sh --dry-run     print every check and every file, change nothing
#   sh setup.sh --uninstall   remove every Nyyrikki account, file and setting
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
	if [ "$NY_DRY" = 0 ] && [ "$NY_UNINSTALL" = 0 ]; then
		warn "Nothing was changed. If an existing setup is in the way, merge it by hand: docs/setup/ssh-hosts.md."
	fi
	ny_cleanup
	exit 1
}

ny_cleanup() {
	if [ -n "$NY_WORK" ] && [ -d "$NY_WORK" ]; then
		rm -rf -- "$NY_WORK" 2>/dev/null || :
	fi
}

# shellcheck disable=SC2329 # called from trap
ny_on_signal() {
	trap '' INT TERM HUP PIPE
	warn "interrupted by SIG$1"
	if [ "$NY_CHANGED" = 1 ]; then
		ny_rollback
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
}

# ny_show VALUE: VALUE cut short and with anything but printable ASCII
# replaced, for error messages.
ny_show() {
	printf '%.80s' "$1" | tr -c '[:print:]' '?'
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

# ny_print_file PATH MODE GENERATED: --dry-run's listing.
ny_print_file() {
	say "would write $1 (mode $2):"
	sed 's/^/    /' "$3" 2>/dev/null || :
}

# --- step 1: checks ---------------------------------------------------------

ny_check() {
	[ "$(id -u)" = 0 ] || die "refused: run as root (sudo sh setup.sh)"

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
	for ny_p in "$NY_CA" "$NY_KRL" "$NY_LIST" "$NY_SSHD" "$NY_LOGIND" "$NY_SCOPE"; do
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
	if [ -f "$NY_KRL" ]; then
		ny_fp=$(ssh-keygen -Q -f "$NY_KRL" "$NY_WORK/ca-check.pub" 2>&1)
		case $? in
		0 | 1) ;;
		*) die "refused: $NY_KRL isn't a valid key revocation list: $ny_fp" ;;
		esac
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
	ny_gen_ca "$NY_WORK/ca" || die "can't write to $NY_WORK"
	put_file "$NY_WORK/ca" "$NY_CA" 0644 || die "can't write $NY_CA"
	if [ ! -f "$NY_KRL" ]; then
		rm -f -- "$NY_WORK/krl"
		ssh-keygen -q -k -f "$NY_WORK/krl" || die "can't create an empty key revocation list"
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
	say "wrote $NY_CA, $NY_KRL and $NY_SSHD; sshd reloaded"
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

# Step 8: what goes into the target's registry entry.
ny_report() {
	say ""
	say "Done. Put this into target $NY_TARGET's ssh block in Nyyrikki's values, and roll out:"
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

# --- --uninstall ---------------------------------------------------------------

ny_uninstall() {
	[ "$(id -u)" = 0 ] || die "refused: run as root"
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
		say "would remove: /etc/sudoers.d/50-nyyrikki-*, $NY_PRINC, the accounts ${NY_LISTED:-(none)} and their homes, $NY_LOGIND, $NY_SCOPE, $NY_SSHD, $NY_DIR"
		for ny_a in $NY_LISTED; do
			has_processes "$ny_a" && say "would refuse: $ny_a has processes"
		done
		ny_cleanup
		exit 0
	fi
	# sshd must accept its configuration before anything changes: a failed
	# check after the drop-in is gone would leave sshd unreloaded.
	ny_t=$("$NY_SSHD_BIN" -t 2>&1) || die "refused: sshd -t fails before any change; fix sshd's configuration first: $ny_t"
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
	say "removed $NY_DIR"
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
	ny_gen_ca "$NY_WORK/ca" || die "can't write to $NY_WORK"
	ny_print_file "$NY_CA" 0644 "$NY_WORK/ca"
	[ -f "$NY_KRL" ] || say "would write $NY_KRL (mode 0644): an empty key revocation list (ssh-keygen -k)"
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
	say "dry run: nothing was changed"
	ny_cleanup
	exit 0
}

# --- main ----------------------------------------------------------------------

main() {
	ny_init
	set -u
	trap 'ny_on_signal INT' INT
	trap 'ny_on_signal TERM' TERM
	trap 'ny_on_signal HUP' HUP
	trap 'ny_on_signal PIPE' PIPE
	trap 'ny_on_exit' EXIT
	for ny_arg in "$@"; do
		case $ny_arg in
		--dry-run) NY_DRY=1 ;;
		--uninstall) NY_UNINSTALL=1 ;;
		*) die "refused: unknown argument $(ny_show "$ny_arg"); only --dry-run and --uninstall" ;;
		esac
	done
	if [ -t 0 ]; then
		die "refused: the data lines come from a terminal: the file is cut off after its main line"
	fi
	ny_read_values
	exec </dev/null
	say "Nyyrikki host setup for target $NY_TARGET"

	NY_WORK=$(mktemp -d "${TMPDIR:-/tmp}/nyyrikki-setup.XXXXXX") || die "can't create a work directory"
	chmod 0700 "$NY_WORK" || die "can't create a work directory"
	: >"$NY_WORK/journal" || die "can't write to $NY_WORK"
	: >"$NY_WORK/saved" || die "can't write to $NY_WORK"

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
	trap - EXIT
	trap '' INT TERM HUP PIPE
	NY_CHANGED=0
	ny_report
	ny_cleanup
	exit 0
}

main "$@" <<'NYYRIKKI_VALUES_END'
