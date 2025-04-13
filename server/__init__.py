from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from server.routes.routes import blureprint as routes
from server.util.path import get_current_working_directory as cwd
import os

class Server:

  __root_path = cwd(__file__)
  
  class Database:

    __db = SQLAlchemy()

    @classmethod
    def set_db(cls, app):
      """
      Initializes the database with the given Flask app.
      """
      return cls.__db.init_app(app)
    
    @classmethod
    def get_db(cls):
      """
      Returns the database instance.
      """
      return cls.__db
      

  def __scanNetworkDB(self):
    """
    Sets the environment for the server.
    """

    return {
      'portscan_db': os.path.join(self.__root_path, 'db', 'portscan.db'),
      'network_db': os.path.join(self.__root_path, 'db', 'network.db'),
    }
  
  def __vulnDB(self):
    return os.path.join(self.__root_path, 'db', 'vuln.db')


  def __routes(self, app : Flask):
    """
    Defines the routes for the server.
    """
    app.register_blueprint(routes)

  def __set_up(self):
    """
    Sets up the server with necessary configurations.
    """

    app = Flask(__name__, template_folder=os.path.join(self.__root_path, 'templates'))
    app.config['SQLALCHEMY_DATABASE_URI'] = self.__vulnDB()
    app.config['SQLALCHEMY_BINDS'] = self.__scanNetworkDB()

    self.Database.set_db(app)

    self.__routes(app)
    
    return app
  
  
  def get_db(self):
    """
    Returns the database instance.
    """
    return self.__db

    
  def start(self, production, host='127.0.0.1', port=5000, debug=True):
    """
    Starts the server on the specified host and port.
    
    Args:
        host (str): The host address to bind the server to.
        port (int): The port number to bind the server to.
        debug (bool): Flag to enable debug mode.
    """


    app = self.__set_up()
    if production:
      app.run(host=host, port=port, debug=False)
    else:
      app.run(host=host, port=port, debug=debug)

        