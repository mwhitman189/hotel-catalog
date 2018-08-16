
from sqlalchemy import Column,Integer,String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
import random, string
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)


Base = declarative_base()
secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))




class Hotel(Base):
    __tablename__ = 'hotel'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    picture = Column(String)
    description = Column(String)
    price = Column(Integer)
    rating = Column(Integer)
    category = Column(String)
    #user_id = Column(Integer, ForeignKey('user.id'))
    #user = relationship(user)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name' : self.name,
            'picture' : self.picture,
            'price' : self.price,
            'description' : self.description,
            'rating' : self.rating
        }

engine = create_engine('sqlite:///hotelListings.db')


Base.metadata.create_all(engine)
