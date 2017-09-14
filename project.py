from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from flask import session as login_session
from flask import make_response
import os
import random
import string
from database_setup import *
from login_decorator import login_required
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import datetime
import httplib2
import json
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"

# Connecting to the database
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

# Creating a session
DBSession = sessionmaker(bind=engine)
session = DBSession()

# This is where we create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(
        random.choice(string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token


    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]


    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data['name']
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code compatible with Python3
    request.get_data()
    code = request.data.decode('utf-8')

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    response = h.request(url, 'GET')[1]
    str_response = response.decode('utf-8')
    result = json.loads(str_response)

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # create a new user if one doesn't already exist
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).first()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).first()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).first()
        return user.id
    except:
        return None


# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
        # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = redirect(url_for('showCatalog'))
        flash("You are now logged out.")
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/temp')
def temp():
   del login_session['access_token']
   del login_session['gplus_id']
   del login_session['username']
   del login_session['email']
   del login_session['picture']
   return redirect('/')


@app.route('/')
@app.route('/catalog/')
def showCatalog():
    hobbies = session.query(Hobby).order_by(asc(Hobby.name))
    items = session.query(Items).order_by(desc(Items.date)).limit(5)
    return render_template('catalog.html',
                            hobbies = hobbies,
                            items = items)


# Adding a hobby

@app.route('/catalog/addhobby', methods=['GET', 'POST'])
@login_required
def addHobby():
    if request.method == 'POST':
        newHobby = Hobby(
            name=request.form['name'],
            user_id=login_session['user_id'])
        print newHobby
        session.add(newHobby)
        session.commit()
        flash('Hobby Successfully Added!')
        return redirect(url_for('showCatalog'))
    else:
        return render_template('addhobby.html')


# Editing a hobby

@app.route('/catalog/<path:hobby_name>/edit', methods=['GET', 'POST'])
@login_required
def editHobby(hobby_name):
    editedHobby = session.query(Hobby).filter_by(name=hobby_name).first()
    hobby = session.query(Hobby).filter_by(name=hobby_name).first()
    creator = getUserInfo(editedHobby.user_id)
    user = getUserInfo(login_session['user_id'])
    if creator.id != login_session['user_id']:
        flash ("You cannot edit this Hobby. This Hobby belongs to %s" % creator.name)
        return redirect(url_for('showCatalog'))
    if request.method == 'POST':
        if request.form['name']:
            editedHobby.name = request.form['name']
        session.add(editedHobby)
        session.commit()
        flash('Hobby Item Successfully Edited!')
        return  redirect(url_for('showCatalog'))
    else:
        return render_template('edithobby.html', hobbies=editedHobby, hobby = hobby)


# Deleting a hobby

@app.route('/catalog/<path:hobby_name>/delete', methods=['GET', 'POST'])
@login_required
def deleteHobby(hobby_name):
    hobbyToDelete = session.query(Hobby).filter_by(name=hobby_name).first()
    creator = getUserInfo(hobbyToDelete.user_id)
    user = getUserInfo(login_session['user_id'])
    if creator.id != login_session['user_id']:
        flash ("You cannot delete this Hobby. This Hobby belongs to %s" % creator.name)
        return redirect(url_for('showCatalog'))
    if request.method =='POST':
        session.delete(hobbyToDelete)
        session.commit()
        flash('Hobby Successfully Deleted! '+hobbyToDelete.name)
        return redirect(url_for('showCatalog'))
    else:
        return render_template('deletehobby.html', hobby=hobbyToDelete)


#Json

@app.route('/catalog/JSON')
def allItemsJSON():
    hobbies = session.query(Hobby).all()
    hobby_dict = [c.serialize for c in hobbies]
    for c in range(len(hobby_dict)):
        items = [i.serialize for i in session.query(Items)\
                    .filter_by(hobby_id=hobby_dict[c]["id"]).all()]
        if items:
            hobby_dict[c]["Item"] = items
    return jsonify(Hobby=hobby_dict)

@app.route('/catalog/hobbies/JSON')
def hobbiesJSON():
    hobbies = session.query(Hobby).all()
    return jsonify(hobbies=[c.serialize for c in hobbies])

@app.route('/catalog/items/JSON')
def itemsJSON():
    items = session.query(Items).all()
    return jsonify(items=[i.serialize for i in items])

@app.route('/catalog/<path:hobby_name>/items/JSON')
def hobbyItemsJSON(hobby_name):
    hobby = session.query(Hobby).filter_by(name=hobby_name).first()
    items = session.query(Items).filter_by(hobby=hobby).all()
    return jsonify(items=[i.serialize for i in items])

@app.route('/catalog/<path:hobby_name>/<path:item_name>/JSON')
def ItemJSON(hobby_name, item_name):
    hobby = session.query(Hobby).filter_by(name=hobby_name).first()
    item = session.query(Items).filter_by(name=item_name,\
                                        hobby=hobby).first()
    return jsonify(item=[item.serialize])


# Hobby Items

@app.route('/catalog/<path:hobby_name>/items/')
def showHobby(hobby_name):
    hobbies = session.query(Hobby).order_by(asc(Hobby.name))
    hobby = session.query(Hobby).filter_by(name=hobby_name).first()
    items = session.query(Items).filter_by(hobby=hobby).order_by(asc(Items.name)).all()
    print items
    count = session.query(Items).filter_by(hobby=hobby).count()
    creator = getUserInfo(hobby.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('public_items.html', hobby = hobby.name, hobbies = hobbies,
                                items = items,
                                count = count)
    else:
        user = getUserInfo(login_session['user_id'])
        return render_template('items.html', hobby = hobby.name, hobbies = hobbies,
                                items = items,
                                count = count,
                                user=user)


# Display a Specific Item

@app.route('/catalog/<path:hobby_name>/<path:item_name>/')
def showItem(hobby_name, item_name):
    item = session.query(Items).filter_by(name=item_name).first()
    creator = getUserInfo(item.user_id)
    hobbies = session.query(Hobby).order_by(asc(Hobby.name))
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('public_itemdetail.html', item = item, hobby = hobby_name,
                                hobbies = hobbies,
                                creator = creator)
    else:
        return render_template('itemdetail.html', item = item, hobby = hobby_name,
                                hobbies = hobbies,
                                creator = creator)


# Only allow users to add an item

@app.route('/catalog/add', methods=['GET', 'POST'])
@login_required
def addItem():
    hobbies = session.query(Hobby).all()
    if request.method == 'POST':
        newItem = Items(
            name=request.form['name'],
            description=request.form['description'],
            picture=request.form['picture'],
            hobby=session.query(Hobby).filter_by(name=request.form['hobby']).first(),
            date=datetime.datetime.now(),
            user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash('Item Successfully Added!')
        return redirect(url_for('showCatalog'))
    else:
        return render_template('additem.html', hobbies=hobbies)


# Only delete an item created by user

@app.route('/catalog/<path:hobby_name>/<path:item_name>/delete', methods=['GET', 'POST'])
@login_required
def deleteItem(hobby_name, item_name):
    itemToDelete = session.query(Items).filter_by(name=item_name).first()
    hobby = session.query(Hobby).filter_by(name=hobby_name).first()
    hobbies = session.query(Hobby).all()
    creator = getUserInfo(itemToDelete.user_id)
    user = getUserInfo(login_session['user_id'])
    if creator.id != login_session['user_id']:
        flash ("You cannot delete this item. This item belongs to %s" % creator.name)
        return redirect(url_for('showCatalog'))
    if request.method =='POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Item Successfully Deleted! '+itemToDelete.name)
        return redirect(url_for('showHobby', hobby_name=hobby.name))
    else:
        return render_template('deleteitem.html', item=itemToDelete)


# Only edit an item created by user

@app.route('/catalog/<path:hobby_name>/<path:item_name>/edit', methods=['GET', 'POST'])
@login_required
def editItem(hobby_name, item_name):
    editedItem = session.query(Items).filter_by(name=item_name).first()
    hobbies = session.query(Hobby).all()
    creator = getUserInfo(editedItem.user_id)
    user = getUserInfo(login_session['user_id'])
    if creator.id != login_session['user_id']:
        flash ("You cannot edit this item. This item belongs to %s" % creator.name)
        return redirect(url_for('showCatalog'))
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['picture']:
            editedItem.picture = request.form['picture']
        if request.form['hobby']:
            hobby = session.query(Hobby).filter_by(name=request.form['hobby']).first()
            editedItem.hobby = hobby
        time = datetime.datetime.now()
        editedItem.date = time
        session.add(editedItem)
        session.commit()
        flash('Hobby Item Successfully Edited!')
        return  redirect(url_for('showHobby', hobby_name=editedItem.hobby.name))
    else:
        return render_template('edititem.html', item=editedItem, hobbies=hobbies)


# static process path removed when deployed

@app.context_processor
def override_url_for():
    return dict(url_for=dated_url_for)

def dated_url_for(endpoint, **values):
    if endpoint == 'static':
        filename = values.get('filename', None)
        if filename:
            file_path = os.path.join(app.root_path, endpoint, filename)
            values['q'] = int(os.stat(file_path).st_mtime)
    return url_for(endpoint, **values)


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalog'))


# This part should always be at the end of a file

if __name__ == '__main__':
    app.secret_key = 'dev_secret_key'
    app.debug = True
    app.run(host = '0.0.0.0', port = 5000)
