from models import User
from HotelsProject import session as login_session


####################
# Helper functions for user objects
####################

def createUser(login_session):
    """
    Used to add OAuth2 authenticated users to database
    """
    newUser = User(username=login_session['username'], email=login_session['email'], picture=login_session['picture'])
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
