#from redis import Redis
import time
from functools import update_wrapper
from flask import Flask, render_template, request, redirect, jsonify, url_for, flash, abort, g, make_response
from flask_httpauth import HTTPBasicAuth
from models import Base, User, Hotel
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import json
import httplib2


auth = HTTPBasicAuth()

APPLICATION_NAME = "Hotel Listings"

engine = create_engine('sqlite:///hotelListings.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']


#TODO: check this
@auth.verify_password
def verify_password(username_or_token, password):
    # Check if it's a token
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(id=user_id).one()
    else:
        user = session.query(User).filter_by(username=username_ousername_or_token).first()
        if not user or not user.verifty_password(password):
            return False
    g.user = user
    return True

#TODO: check this
@app.route('/clientOAuth')
def start():
    return render_template('client_OAuth.html')


@app.route('/oauth/<provider>', methods=['POST'])
def login(provider):
    # Step 1: Parse the authorization code
    auth_code = request.json.get('auth_code')
    print "Step 1 complete: received auth code %s" % auth_code
    if provider == 'google':
        # Step 2: Exchange auth code for a token
        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Confirm that the access token is valid
        access_token = credentials.access_token
        url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token) # NOQA
        h = httplib2.Http()
        result = json.loads(h.request(url, 'GET')[1])
        # If there was an error in the access token info, abort
        if result.get('error') is not None:
            response = make_response(json.dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'

        # Verify that the access token is used for the intended user.
        gplus_id = credentials.id_token['sub']
        if result['user_id'] != gplus_id:
            response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Verify that the access token is valid for this app.
        if result['issued_to'] != CLIENT_ID:
            response = make_response(json.dumps("Token's client ID does not match app's."), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        stored_credentials = login_session.get('credentials')
        stored_gplus_id = login_session.get('gplus_id')
        if stored_credentials is not None and gplus_id == stored_gplus_id:
            response = make_response(json.dumps('Current user is already connected.'), 200)
            response.headers['Content-Type'] = 'application/json'
            return response
        print "Step 2 Complete! Access Token : %s " % credentials.access_token

        # Step 3: Find User or make a new one
        # Get user info
        h = httplib2.Http()
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt':'json'}
        answer = requests.get(userinfo_url, params=params)

        data = answer.json()

        name = data['name']
        picture = data['picture']
        email = data['email']

        # Check is user exists; if not, make a new one
        user = session.query(User).filter_by(email=email).first()
        if not user:
            user = User(username=name, picture=picture, email=email)
            session.add(user)
            session.commit()

        # Step 4: Make a token
        token = user.generate_auth_token(600)

        # Step 5: Send token back to client
        return jsonify({'token': token.decode('ascii')})

        # Return jsonify({'token': token.decode('ascii'), 'duration': 600})
    else:
        return "Unrecoginized Provider"


@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


@app.route('/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        print "Missing arguments"
        abort(400)

    if session.query(User).filter_by(username=username).first() is not None:
        print "Existing user"
        user = session.query(User).filter_by(username=username).first()
        return jsonify({'message':'User already exists'}), 200

    user = User(username=username)
    user.hash_password(password)
    session.add(user)
    session.commit(
    return jsonify({ 'username': user.username }), 201

@app.route('/api/users/<int:id>')
def get_user(id):
    user = session.query(User).filter_by(id=id).one()
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({ 'data': 'Hello, %s!' % g.user.username })


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
    if request.method == 'POST':
        new_hotel = Hotel(
            name=request.form['name'],
            picture=request.form['picture'],
            description=request.form['description'],
            price=request.form['price'],
            rating=request.form['rating'],
            category=request.form['category'],
            )
        session.add(new_hotel)
        session.commit()
        flash("New hotel added!")
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
