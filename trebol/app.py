#!/usr/bin/env python
# -*- coding: utf-8 -*-

import tornado.ioloop
import tornado.options
import tornado.web
import motor

from handlers import *
from tornado.options import define, options
import os.path

define("port", default=3000, help="run on the given port", type=int)


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", MainHandler),
            (r"/login/?", LoginHandler),
            (r"/logout/?", LogoutHandler),
            (r"/device/create/?", DeviceCreateHandler),
            (r"/device/(?P<slug>.+)/update/?", DeviceUpdateHandler),
            (r"/device/socket/?", DeviceSocketHandler),
            (r"/user/create/?", UserCreateHandler),
            (r"/user/list/?", UserListHandler),
            (r"/user/(?P<id>\d+)/update/?", UserUpdateHandler),
        ]
        settings = dict(
            cookie_secret="__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            login_url="/login/",
            xsrf_cookies=True,
            db=motor.MotorClient("localhost", 27017).trebol,
            debug=True,
        )

        try:
            import deploy
        except ImportError:
            pass
        else:
            settings.update(deploy.settings)

        tornado.web.Application.__init__(self, handlers, **settings)


def main():
    tornado.options.parse_command_line()
    app = Application()
    app.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()
