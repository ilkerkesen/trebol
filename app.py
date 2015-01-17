#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import tornado.escape
import tornado.ioloop
import tornado.options
import tornado.web
import tornado.websocket
import motor

import ast
import bcrypt
import os.path
import uuid
import time

from tornado.options import define, options

define("port", default=3000, help="run on the given port", type=int)


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", MainHandler),
            (r"/login/?", LoginHandler),
            (r"/logout/?", LogoutHandler),
            (r"/device/create/?", DeviceCreateHandler),
            (r"/device/(?P<slug>.+)/update/?", DeviceUpdateHandler),
        ]
        settings = dict(
            cookie_secret="__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            login_url="/login/",
            xsrf_cookies=True,
            db=motor.MotorClient('localhost', 27017).trebol,
        )
        tornado.web.Application.__init__(self, handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        user_json = self.get_secure_cookie("user")
        if user_json:
            return tornado.escape.json_decode(user_json)
        else:
            return None

    def get_flash(self):
        flash = self.get_secure_cookie("flash")
        self.clear_cookie("flash")
        return flash

    def get_message(self):
        message = self.get_secure_cookie("message")
        self.clear_cookie("message")
        if message:
            message = ast.literal_eval(message)
        return message


class MainHandler(BaseHandler):
    @tornado.web.authenticated
    @tornado.gen.coroutine
    def get(self):
        db = self.settings["db"]
        cursor = db.devices.find().sort('name', 1)
        count = yield cursor.count()
        devices = yield cursor.to_list(count)

        self.render(
            "index.html",
            username=self.get_current_user(),
            devices=devices,
            message=self.get_message()
        )


class LoginHandler(BaseHandler):
    def get(self):
        self.render("login.html", notification=self.get_flash())

    @tornado.gen.coroutine
    def post(self):
        users = self.settings["db"].users
        email = self.get_argument("email", "")
        password = self.get_argument("password", "").encode()
        user = yield users.find_one({"email": email})

        if user and user['hash'] and \
           bcrypt.hashpw(password, user["hash"].encode()) == user["hash"]:
            self.set_current_user(email)
            self.redirect(self.get_argument("next", u"/"))
        else:
            self.set_secure_cookie("flash", "Authorization Failure.")
            self.redirect(self.settings["login_url"])

    def set_current_user(self, user):
        if user:
            self.set_secure_cookie("user", tornado.escape.json_encode(user))
        else:
            self.clear_cookie("user")


class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("user")
        self.redirect(self.get_argument("next", "/"))


class DeviceCreateHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        self.render("device_create.html", message=self.get_message())

    @tornado.gen.coroutine
    def post(self):
        db = self.settings["db"]
        name = self.get_argument("name", "")
        password = self.get_argument("password", "").encode()
        device = yield db.devices.find_one({"name": name})

        if device is not None:
            self.set_secure_cookie(
                "message", 
                str({
                    "type": "danger",
                    "text": "Device already exists.",
                }))
            self.redirect("/device/create/")
        elif name and password:
            password_hash = bcrypt.hashpw(password, bcrypt.gensalt(8))
            new_device = yield db.devices.insert({
                "name": name,
                "hash": password_hash,
                "address": None,
            })
            self.set_secure_cookie(
                "message",
                str({
                    "type": "success",
                    "text": "Device {} added succesfully.".format(name),
                }))
            self.redirect("/device/create/")
        else:
            self.set_secure_cookie(
                "message",
                str({
                    "type": "danger",
                    "text": "Please enter a valid device.",
                }))
            self.redirect('/device/create/')


class DeviceUpdateHandler(BaseHandler):
    @tornado.web.authenticated
    @tornado.gen.coroutine
    def get(self, slug):
        db = self.settings["db"]
        name = slug.rstrip("/")
        device = yield db.devices.find_one({"name": name})

        if device is None:
            raise tornado.web.HTTPError(404)

        message = self.get_secure_cookie("message", "")
        self.render(
            "device_update.html", device=device["name"], message=message)

    @tornado.gen.coroutine
    def post(self, slug):
        db = self.settings["db"]
        name = slug.rstrip("/")
        device = yield db.devices.find_one({"name": name})
        action = self.get_argument("action", "")

        if action not in ("update", "delete") or device is None:
            raise tornado.web.HTTPError(404)

        if action == "delete":
            response = yield db.devices.remove({"name": name})
            if response["err"] is None:
                msg = {
                    "type": "success",
                    "text": "Device {} deleted.".format(name),
                }
            else:
                msg = {
                    "type": "danger",
                    "text": "Device {} could not be deleted: {}".format(
                        name, response["err"])
                }
            redirect = "/"
        elif action == "update":
            new_name = self.get_argument("name", None)
            new_password = self.get_argument("password", None)

            if new_name is None:
                msg = {
                    "type": "danger",
                    "text": "Please enter a device name.",
                }
                redirect = "/device/{}/update/".format(name)
            else:
                update = {"name": new_name}
                if new_password is not None:
                    update["password"] = bcrypt.hashpw(
                        new_password, bcrpyt.gensalt(8))
                response = yield db.devices.update(
                    {"name": name}, {"$set": update})

                if response["err"] is None:
                    msg = {
                        "type": "success",
                        "text": "Device updated successfully."
                    }
                    redirect = "/device/{}/update".format(new_name)
                else:
                    msg = {
                        "type": "alert",
                        "text": "Device update failure: {}".format(
                            response["err"])
                    }
                    redirect = "/device/{}/update".format(name)
        self.set_secure_cookie("message", str(msg))
        self.redirect(redirect)


def main():
    tornado.options.parse_command_line()
    app = Application()
    app.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()
