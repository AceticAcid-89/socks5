# encoding: utf-8

import getpass
import logging
import platform


# log default folder is windows desktop/socks_proxy.log
#  linux /var/log/socks_proxy.log
windows_log_path = "C:\\Users\\%s\\Desktop\\socks_proxy.log"
linux_log_path = "/var/log/socks_proxy.log"
run_platform = platform.platform()
if run_platform.startswith("Windows"):
    user = getpass.getuser()
    log_path = windows_log_path % user
else:
    log_path = linux_log_path


log_format = '[%(asctime)s %(filename)s:%(lineno)d' \
             ' %(funcName)s] [PID:%(thread)d] ' \
             '[%(threadName)s] [%(levelname)s] %(message)s'
date_format = '%Y-%m-%dT%H:%M:%S'
logging.basicConfig(level=logging.DEBUG,
                    format=log_format,
                    datefmt=date_format,
                    filename=log_path)


def debug(msg):
    logging.debug(msg)


def info(msg):
    logging.info(msg)


def warn(msg):
    logging.warning(msg)


def error(msg):
    logging.error(msg)
