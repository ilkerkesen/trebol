#!/usr/bin/env python
# -*- coding: utf-8 -*-

import functools
from tornado.web import HTTPError

__all__ = ["is_admin"]


def is_admin(method):
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        if self.current_user["group"] != "admin":
            raise HTTPError(404)
        return method(self, *args, **kwargs)
    return wrapper
