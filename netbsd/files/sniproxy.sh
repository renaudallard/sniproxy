#!@RCD_SCRIPTS_SHELL@
#
# PROVIDE: sniproxy
# REQUIRE: NETWORKING

. /etc/rc.subr

name="sniproxy"
rcvar=${name}
command="@PREFIX@/sbin/${name}"
required_files="@PKG_SYSCONFDIR@/sniproxy.conf"
pidfile="@VARBASE@/run/${name}.pid"

load_rc_config $name
run_rc_command "$1"
