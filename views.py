#from redis import Redis
import time
from functools import update_wrapper
from flask import request, g
from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from models import Base, Hotel
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

app = Flask(__name__)

#CLIENT_ID = json.loads(
#    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Hotel Listings"

engine = create_engine('sqlite:///hotelListings.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()



@app.route('/')
@app.route('/hotels/')
def listHotels():
    hotels = session.query(Hotel).all()
    return render_template('list_hotels.html', hotels=hotels)


@app.route('/hotel/categories/')
def listHotelCategories():
    categories = session.query(Hotel.category).all()
    return render_template('list_hotel_categories.html', categories=categories)


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
