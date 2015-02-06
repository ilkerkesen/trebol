#!/usr/bin/env python
# -*- coding: utf-8 -*-

import tornado.escape
import tornado.web
import tornado.websocket
import motor
import logging
import ast
import bcrypt

from interface import *

__all__ = [
    "MainHandler", "LoginHandler", "LogoutHandler",
    "DeviceCreateHandler", "DeviceUpdateHandler", "DeviceSocketHandler",
    "UserCreateHandler", "UserListHandler", "UserUpdateHandler",
]


class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        user_json = self.get_secure_cookie("user")
        if user_json:
            return tornado.escape.json_decode(user_json)
        else:
            return None

    def set_message(self, kind, text):
        msg = {"type": kind, "text": text}
        self.set_secure_cookie(str(msg))

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
        self.render("login.html", message=self.get_message())

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
            self.set_message("danger", "Authorization Failure.")
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
        key = self.get_argument("key", "")
        device = yield db.devices.find_one({"name": name})

        if device is not None:
            kind = "danger"
            text = "Device already exists."
        elif name and key:
            yield db.devices.insert({
                "name": name,
                "key": key,
                "address": None,
            })
            kind = "success"
            text = "Device {} added succesfully".format(name)
        else:
            kind = "danger"
            text = "Please enter a valid device."

        self.set_message(kind, text)
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
            "device_update.html", device=device, message=message)

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
                kind = "success"
                text = "Device {} deleted.".format(name)
            else:
                kind = "danger"
                text = "Device {} could not be deleted: {}".format(
                    name, response["err"])
            redirect = "/"
        elif action == "update":
            new_name = self.get_argument("name", None)
            new_key = self.get_argument("key", None)

            if new_name is None:
                kind = "danger"
                text = "Please enter a device name."
                redirect = "/device/{}/update/".format(name)
            elif new_key is None:
                kind = "danger"
                text = "Please enter a key for device."
                redirect = "/device/{}/update/".format(name)
            else:
                update = {"name": new_name, "key": new_key}
                response = yield db.devices.update(
                    {"name": name}, {"$set": update})

                if response["err"] is None:
                    kind = "success"
                    text = "Device updated succesfully."
                else:
                    kind = "alert"
                    text = "Device update failure: {}".format(response["err"])
                redirect = "/device/{}/update".format(name)

        self.set_message(kind, text)
        self.redirect(redirect)


class UserCreateHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        self.render("user_create.html", message=self.get_message())

    @tornado.gen.coroutine
    def post(self):
        db = self.settings["db"]
        email = self.get_argument("email", "")
        password = self.get_argument("password", "")
        user = yield db.users.find_one({"email": email})

        if user is not None:
            kind = "danger"
            text = "User already exists."
        elif email and password:
            yield create_new_user(db, email, password)
            kind = "success"
            text = "User {} added succesfully.".format(email)
        else:
            kind = "danger"
            text = "Please enter  valid user."

        self.set_message(kind, text)
        self.redirect("/user/create/")


class UserListHandler(BaseHandler):
    @tornado.web.authenticated
    @tornado.gen.coroutine
    def get(self):
        cursor = self.settings["db"].users.find().sort('_id', 1)
        count = yield cursor.count()
        users = yield cursor.to_list(count)
        self.render("user_list.html", users=users, message=self.get_message())


class UserUpdateHandler(BaseHandler):
    @tornado.web.authenticated
    @tornado.gen.coroutine
    def get(self, id):
        user = yield self.settings["db"].users.find_one({"_id": int(id)})
        if user is None:
            raise tornado.web.HTTPError(404)

        self.render("user_update.html", user=user, message=self.get_message())

    @tornado.gen.coroutine
    def post(self, id):
        db = self.settings["db"]
        id = int(id)
        user = yield db.users.find_one({"_id": id})
        action = self.get_argument("action", "")

        if action not in ("update", "delete") or user is None:
            raise tornado.web.HTTPError(404)

        if action == "delete":
            response = yield db.users.remove({"_id": id})
            if response["err"] is None:
                kind = "success"
                text = "User {} deleted.".format(user["email"])
            else:
                kind = "danger"
                text = "User {} could not be deleted: {}".format(
                    user["email"], response["err"])
            redirect = "/"
        elif action == "update":
            new_email = self.get_argument("email", None)
            new_pass = self.get_argument("password", None)

            if new_email is None:
                kind = "danger"
                text = "Please enter an email address."
                redirect = "/user/{}/update/".format(name)
            else:
                update = {"email": new_email}
                if new_pass is not None:
                    update.update({"hash": bcrypt.hashpw(
                        new_pass.encode(), bcrypt.gensalt(8))})
                response = yield db.users.update(
                    {"_id": id}, {"$set": update})
                redirect = "/user/{}/update".format(str(id))

                if response["err"] is None:
                    kind = "success"
                    text = "User updated successfully."
                else:
                    kind = "danger"
                    text = "User update failure: {}".format(response["err"])

        self.set_message(kind, text)
        self.redirect(redirect)


class DeviceSocketHandler(tornado.websocket.WebSocketHandler):
    devices = set()

    def check_origin(self, origin):
        return True

    @tornado.gen.coroutine
    def open(self):
        if not self.request.headers.has_key("X-Device-Name"):
            self.write_message("missing-device-name")
            self.close()
            self.finish()

        if not self.request.headers.has_key("X-Device-Key"):
            self.write_message("missing-device-key")
            self.close()
            self.finish()

        name = self.request.headers["X-Device-Name"]
        key = self.request.headers["X-Device-Key"]
        device = yield self.settings["db"].devices.find_one(
            {"name": name, "key": key})

        if device is None:
            self.write_message("device-does-not-exist")
            self.close()

        DeviceSocketHandler.devices.add(self)
        logging.info("A device connected.")

    def on_close(self):
        DeviceSocketHandler.devices.remove(self)
        logging.info("A device disconnected.")
