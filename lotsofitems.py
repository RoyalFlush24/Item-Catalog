from sqlalchemy import create_engine
from database_setup import *
from sqlalchemy.orm import sessionmaker
import datetime

engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Delete Users if exisitng.

session.query(User).delete()

# Delete Items if exisitng.

session.query(Items).delete()

# Delete Hobbies if exisitng.

session.query(Hobby).delete()


# Creating a user

User1 = User(name="Nuri Cherif",
              email="nuricherif@gmail.com",
              picture='http://dummyimage.com/200x200.png/ff')
session.add(User1)
session.commit()


# Creating some hobbies

Hobby1 = Hobby(name="Cars",
                      user_id=1)
session.add(Hobby1)
session.commit()

Hobby2 = Hobby(name="Sports",
                      user_id=2)
session.add(Hobby2)
session.commit

Hobby3 = Hobby(name="Beaches",
                      user_id=1)
session.add(Hobby3)
session.commit()

Hobby4 = Hobby(name="Resorts",
                      user_id=1)
session.add(Hobby4)
session.commit()

Hobby5 = Hobby(name="Food",
                      user_id=1)
session.add(Hobby5)
session.commit()

# Populating different item in a hobby for testing

Item1 = Items(name="Old School Car",
               date=datetime.datetime.now(),
               description="Classic car to remember old times.",
               picture="https://i.pinimg.com/736x/bf/15/d8/bf15d81ded0819bc3fd22b07a9399edf--electric-blue-mustang-mach-.jpg",
               hobby_id=1,
               user_id=1)
session.add(Item1)
session.commit()

Item2 = Items(name="Sports Car",
               date=datetime.datetime.now(),
               description="Sport/Luxury vehicle.",
               picture="https://i.pinimg.com/736x/82/f0/cd/82f0cd5c3d9d8e75a1a04967e9f3c7bf--sportcars-lamborghini-aventador.jpg",
               hobby_id=1,
               user_id=1)
session.add(Item2)
session.commit()

Item3 = Items(name="Luxurious Car",
               date=datetime.datetime.now(),
               description="A Luxury vehicle.",
               picture="http://www.hdcarwallpapers.com/walls/2016_mansory_rolls_royce_wraith_palm_edition_999_2-HD.jpg",
               hobby_id=1,
               user_id=1)
session.add(Item3)
session.commit()

print "Your data has been populated in your database!"
