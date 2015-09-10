import os
import re
import random
import hashlib
import hmac
import time
from string import letters

#Using webapp2 framework and jiaja2 template engine.
import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

secret = "hwew23042jba[.spw02msh2k[w]s"

#Hash functions used to hash cookies's value.
def hash_str(s):
	return hmac.new(secret, s).hexdigest()

def make_secure_val(val):
	return '%s|%s' % (val, hash_str(val))

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

#Create some convenient functions.
class MainHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
    
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
    		'Set-Cookie', '%s=%s; Path=/' 
    		% (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        if cookie_val:
            return check_secure_val(cookie_val)
    
    #utilize user's id in the database to be the val to set cookie.
    #this id is given by the database automatically
    #this function is used to set the cookie
    def login(self, user):
    	self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

#Home page handler
class MainPage(MainHandler):
    def get(self):
        last_modified = Page.last()
        p = Page.by_address('/')
        content = ""
        if p:
            content = p.content
        user_id = self.read_secure_cookie('user_id')
        if user_id:
            user = User.by_id(int(user_id))
            self.render('front-page.html', username = user.name, 
                last_modified = last_modified, address = '/', 
                loggedin = user_id, content = content)
        else:
            self.render('front-page.html', loggedin = user_id, 
                last_modified = last_modified, address = '/', 
                content = content)

#Regular expression for check valid signup
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(MainHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            u = User.by_name(username)
            if u:
                error_username = 'That user already exists.'
                self.render('signup-form.html', error_username = error_username)
            else:
                u = User.register(username, password, email)
                u.put()
                self.login(u)
                self.redirect('/')

#If user's login information is valid, log in user and 
#bring user to home page and set cookie.
class Login(MainHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect("/")
        else:
            error = 'Invalid login'
            self.render('login-form.html', username = username, error = error)

#Set cookie to empty, redirect user to home page.
class Logout(MainHandler):
    def get(self):
        self.logout()
        self.redirect('/')

#Functions to hash user's password
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

#User entity
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(name = name, pw_hash = pw_hash, email = email)

    @classmethod
    #used to check if the (username, password) pair is vaild to log in
    #once the user can login successfully, use login function in
    #MainHandler to set cookie
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

#Permapage for a specific exist wiki.
class Page(db.Model):
    address = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    @classmethod
    def by_address(cls, address):
        p = Page.all().filter('address =', address).get()
        return p

    @classmethod
    def last(cls):
        last_modified = Page.all().order('-last_modified').run(limit=10)
        return last_modified

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

#Create a version page after every edit to put in VersionPage entity.
#This will be useful to list history for specific wiki.
class VersionPage(db.Model):
    parent_address = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    version_id = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def by_id(cls, parent_address, version_id):
        version = VersionPage.all().filter('parent_address =', 
            parent_address).filter('version_id =', version_id).get()
        return version

    @classmethod
    def history(cls, parent_address):
        history = VersionPage.all().filter('parent_address =', 
            parent_address).order('-created')
        return history

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('post.html', p = self)

#Show the history page with all history versions listed.
class HistoryPage(MainHandler):
    def get(self, address):
        history = VersionPage.history(address)
        user_id = self.read_secure_cookie('user_id')
        if user_id:
            user = User.by_id(int(user_id))
            self.render('history.html', history = history, loggedin = user_id, 
                address = address, username = user.name)
        else:
            self.render('history.html', history = history, 
                loggedin = user_id, address = address)

#Edit Handler is used to edit any page.
class EditPage(MainHandler):
    def get(self, address):
        user_id = self.read_secure_cookie('user_id')
        #Edit is not allowed, if user haven't logged in.
        if not user_id:
            self.redirect('/login')
        else:
            user = User.by_id(int(user_id))
            v = self.request.get('v')
            if v:
                version = VersionPage.by_id(address, v)
                content = ""
                if version:
                    content = version.content
                    self.render('page.html', address = address, 
                        username = user.name, content = content)
                else:
                    self.redirect('/404')
            else:
                p = Page.by_address(address)
                content = ""
                if p:
                    content = p.content
                self.render('page.html', address = address, 
                    username = user.name, content = content)

    def post(self, address):
        content = self.request.get('content')
        if content:
            p = Page.by_address(address)
            if p:
                p.content = content
            else:
                p = Page(address = address, content = content)
            p.put()
            
            #After every new edit, create a new version to store in the datastore.
            v = VersionPage(parent_address = address, content = content)
            v.put()
            v.version_id = str(v.key().id())
            v.put()

            time.sleep(0.1)
            self.redirect(address)
        else:
            user_id = self.read_secure_cookie('user_id')
            user = User.by_id(int(user_id))
            error = "Content can not be empty!"
            self.render('page.html', address = address, 
                username = user.name, error = error)

class WikiPage(MainHandler):
    def get(self, address):
        v = self.request.get('v')
        if v:
            version = VersionPage.by_id(address, v)
            content = ""
            if version:
                user_id = self.read_secure_cookie('user_id')
                if user_id:
                    user = User.by_id(int(user_id))
                    content = version.content
                    self.render('permapage.html', address = address, 
                        version_id = version.version_id, username = user.name, 
                        loggedin = user_id, page = version)
                else:
                    self.render('permapage.html', page = version, 
                        address = address, loggedin = user_id)
            else:
                self.redirect('/404')
        else:
            p = Page.by_address(address)
            if not p:
                self.redirect('/_edit' + address)
            else:
                user_id = self.read_secure_cookie('user_id')
                if user_id:
                    user = User.by_id(int(user_id))
                    self.render('permapage.html', page = p, loggedin = user_id, 
                        username = user.name, address = address)
                else:
                    self.render('permapage.html', page = p, 
                        address = address, loggedin = user_id)

#If the url user typed in is invalid, redirect to the 404 error page.
class ErrorPage(MainHandler):
    def get(self):
        self.render('404.html')

#Regular expression to match wiki's url.
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/', MainPage), 
                               ('/404', ErrorPage), 
	                           ('/signup', Signup), 
	                           ('/login', Login), 
                               ('/logout', Logout), 
                               ('/_history' + PAGE_RE, HistoryPage), 
                               ('/_edit' + PAGE_RE, EditPage), 
                               (PAGE_RE, WikiPage), 
                               ],
                               debug=True)
