#from redis import Redis
import time
import random
import string
from functools import update_wrapper
from flask import Flask, render_template, request, redirect, jsonify, url_for, flash, abort, g, make_response, session as login_session
from flask_httpauth import HTTPBasicAuth
from models import Base, Hotel
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
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


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
