#from redis import Redis
from apiclient import discovery
import time
import random
import string
from functools import update_wrapper
from flask import Flask, render_template, request, redirect, jsonify, url_for, flash, abort, g, make_response, session as login_session
from flask_httpauth import HTTPBasicAuth
from models import Base, Hotel, User
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from oauth2client import client
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import json
import httplib2
import requests


auth = HTTPBasicAuth()

APPLICATION_NAME = "Hotel Listings"
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
CLIENT_SECRET_FILE = 'client_secrets.json'


engine = create_engine('sqlite:///hotelListings.db?check_same_thread=False')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)




def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session['email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(
        string.ascii_uppercase + string.digits)for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['GET', 'POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code to a credentials object
        if not request.headers.get('X-Requested-With'):
            abort(403)

        flow = flow_from_clientsecrets('client_secrets.json', scope='profile')
        flow.redirect_uri = 'postmessage'
        # Exchange auth code for access token, refresh token, and ID token
        credentials = flow.step2_exchange(code)

    except FlowExchangeError:
        response = make_response(json.dumps("Failed to upgrade the authorization code."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid
    access_token = credentials.access_token
    url = (
        'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
        % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        respose.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the inteded user
    # Get profile info from ID token
    userid = credentials.id_token['sub']
    email = credentials.id_token['email']

    if result['user_id'] != userid:
        response = make_response(json.dumps("Token's user ID doesn't match the given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps("Token's client ID does not match app's"), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_userid = login_session.get('userid')
    if stored_access_token is not None and userid == stored_userid:
        login_session['access_token'] = credentials.access_token
        response = make_response(json.dumps('Current user is already connected'), 200)
        flash("Current user is already connected!")
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use
    login_session['access_token'] = credentials.access_token
    login_session['userid'] = userid

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # Check if user is already if database, and if not, creates a new user object
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
    output += '" style = "width: 300px; height: 300px;border-radius: 150px;"> '
    flash("You are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# Disconnect: Revoke the current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    credentials = login_session.get('access_token')
    if credentials is None:
        response = make_response(json.dumps('Current user not connected'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Execute HTTP GET request to revoke the current token
    access_token = credentials
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reset the user's session
        del login_session['access_token']
        del login_session['userid']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # The given token was invalid
        response = make_response(json.dumps('Failed to revoke the user token'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response



### JSON APIs to view Hotel information ###
@app.route('/hotels/JSON')
def listHotelsJSON():
    hotels = session.query(Hotel).all()
    return jsonify(hotels=[h.serialize for h in hotels])


@app.route('/hotel/categories/JSON')
def listHotelCategoriesJSON():
    categories = session.query(Hotel.category).group_by(
        Hotel.category).order_by(Hotel.category).all()
    return jsonify(categories=[c.serialize for c in categories])


@app.route('/hotels/<category>/JSON')
def listHotelsByCategoryJSON(category):
    hotels = session.query(Hotel).filter_by(
        category=category).all()
    return jsonify(hotels=[h.serialize for h in hotels])


@app.route('/')
@app.route('/hotels/')
def listHotels():
    categories = session.query(Hotel.category).group_by(
        Hotel.category).order_by(Hotel.category).all()
    hotels_by_category = session.query(Hotel).group_by(Hotel.category).all()
    hotels = session.query(Hotel).all()
    for hotel in hotels_by_category:
        print hotel.picture
    return render_template(
        'list_hotels.html', hotels=hotels, categories=categories, hotels_by_category=hotels_by_category)


@app.route('/hotel/categories/')
def listHotelCategories():
    categories = session.query(Hotel.category).group_by(
        Hotel.category).order_by(Hotel.category).all()
    return render_template(
        'list_hotel_categories.html', categories=categories)


@app.route('/hotels/<category>/')
def listHotelsByCategory(category):
    hotels = session.query(Hotel).filter_by(category=category).all()
    return render_template('list_hotels_by_category.html', hotels=hotels)


@app.route('/hotel/new/', methods=['GET', 'POST'])
def newHotel():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        new_hotel = Hotel(
            name=request.form['name'],
            picture=request.form['picture'],
            description=request.form['description'],
            price=request.form['price'],
            rating=request.form['rating'],
            category=request.form['category'],
            user_id=login_session['user_id'],
            )
        session.add(new_hotel)
        session.commit()
        flash("Success! %s was added to the database." % new_hotel.name)
        return redirect(url_for('listHotels'))
    else:
        return render_template('new_hotel.html')


@app.route('/hotel/<int:hotel_id>/')
def showHotel(hotel_id):
    hotel = session.query(Hotel).filter_by(id=hotel_id).one()
    return render_template('show_hotel.html', hotel=hotel)


@app.route('/hotel/<int:hotel_id>/edit/', methods=['GET', 'POST'])
def editHotel(hotel_id):
    hotel_to_edit = session.query(Hotel).filter_by(id=hotel_id).one()
    if request.method == 'POST':
        if request.form['name']:
            hotel_to_edit.name = request.form['name']
        if request.form['picture']:
            hotel_to_edit.picture = request.form['picture']
        if request.form['description']:
            hotel_to_edit.description = request.form['description']
        if request.form['price']:
            hotel_to_edit.price = request.form['price']
        if request.form['rating']:
            hotel_to_edit.rating = request.form['rating']
        if request.form['category']:
            hotel_to_edit.category = request.form['category']
            session.add(hotel_to_edit)
            session.commit()
            flash("Hotel successfully edited!")
            return redirect(url_for('showHotel', hotel_id=hotel_id))
    else:
        return render_template('edit_hotel.html', hotel_id=hotel_id, hotel=hotel_to_edit)




### Initialize App ###
if __name__ == '__main__':
    app.secret_key = 'unbelievably_secret_key'
    app.debug = True
    app.run(host = '0.0.0.0', port = 8000)
