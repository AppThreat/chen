package io.appthreat.pysrc2cpg.passes

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.appthreat.x2cpg.passes.frontend.{ImportsPass, XTypeHintCallLinker}
import io.shiftleft.semanticcpg.language.*

import java.io.File
import io.appthreat.x2cpg.passes.frontend.ImportsPass.*
import io.shiftleft.semanticcpg.language.NoResolve

import scala.collection.immutable.Seq
class TypeRecoveryPassTests extends PySrc2CpgFixture(withOssDataflow = false):

  "literals declared from built-in types" should {
      lazy val cpg = code("""
        |x = 123
        |
        |def foo_shadowing():
        |   x = "foo"
        |
        |z = {'a': 123}
        |z = [1, 2, 3]
        |z = (1, 2, 3)
        |# This should fail, as tuples are immutable
        |z.append(4)
        |""".stripMargin).cpg

      "resolve 'x' identifier types despite shadowing" in {
          val List(xOuterScope, xInnerScope) = cpg.identifier("x").take(2).l
          xOuterScope.dynamicTypeHintFullName shouldBe Seq("__builtin.int")
          xInnerScope.dynamicTypeHintFullName shouldBe Seq("__builtin.int")
      }

      "resolve 'y' and 'z' identifier collection types" in {
          val List(zDict, zList, zTuple) = cpg.identifier("z").take(3).l
          zDict.dynamicTypeHintFullName shouldBe Seq(
            "__builtin.dict",
            "__builtin.list",
            "__builtin.tuple"
          )
          zList.dynamicTypeHintFullName shouldBe Seq(
            "__builtin.dict",
            "__builtin.list",
            "__builtin.tuple"
          )
          zTuple.dynamicTypeHintFullName shouldBe Seq(
            "__builtin.dict",
            "__builtin.list",
            "__builtin.tuple"
          )
      }

      "resolve 'z' identifier calls conservatively" in {
          val List(zAppend) = cpg.call("append").l
          zAppend.methodFullName shouldBe "<unknownFullName>"
          // Since we don't have method nodes with this full name, this should belong to the call linker namespace
          zAppend.callee.astParentFullName.headOption shouldBe Some(XTypeHintCallLinker.namespace)
          zAppend.dynamicTypeHintFullName shouldBe Seq(
            "__builtin.dict.append",
            "__builtin.list.append",
            "__builtin.tuple.append"
          )
      }
  }

  "call from a function from an external type" should {

      lazy val cpg = code("""
        |from slack_sdk import WebClient
        |from sendgrid import SendGridAPIClient
        |
        |client = WebClient(token="WOLOLO")
        |sg = SendGridAPIClient("SENGRID_KEY_WOLOLO")
        |
        |def send_slack_message(chan, msg):
        |    client.chat_postMessage(channel=chan, text=msg)
        |
        |response = sg.send(message)
        |""".stripMargin).cpg

      "resolve correct imports via tag nodes" in {
          val List(
            webClientM: UnknownMethod,
            webClientT: UnknownTypeDecl,
            sendGridM: UnknownMethod,
            sendGridT: UnknownTypeDecl
          ) = cpg.call.where(_.referencedImports).tag.toResolvedImport.toList: @unchecked
          webClientM.fullName shouldBe "slack_sdk.WebClient.__init__"
          webClientT.fullName shouldBe "slack_sdk.WebClient"
          sendGridM.fullName shouldBe "sendgrid.SendGridAPIClient.__init__"
          sendGridT.fullName shouldBe "sendgrid.SendGridAPIClient"
      }

      "resolve 'sg' identifier types from import information" in {
          val List(sgAssignment, sgElseWhere) = cpg.identifier("sg").take(2).l
          sgAssignment.typeFullName shouldBe "sendgrid.SendGridAPIClient"
          sgElseWhere.typeFullName shouldBe "sendgrid.SendGridAPIClient"
      }

      "resolve 'sg' call path from import information" in {
          val List(apiClient) = cpg.call("SendGridAPIClient").l
          apiClient.methodFullName shouldBe "sendgrid.SendGridAPIClient.__init__"
          val List(sendCall) = cpg.call("send").l
          sendCall.methodFullName shouldBe "sendgrid.SendGridAPIClient.send"
      }

      "resolve 'client' identifier types from import information" in {
          val List(clientAssignment, clientElseWhere) = cpg.identifier("client").take(2).l
          clientAssignment.typeFullName shouldBe "slack_sdk.WebClient"
          clientElseWhere.typeFullName shouldBe "slack_sdk.WebClient"
      }

      "resolve 'client' call path from identifier in child scope" in {
          val List(client) = cpg.call("WebClient").l
          client.methodFullName shouldBe "slack_sdk.WebClient.__init__"
          val List(postMessage) = cpg.call("chat_postMessage").l
          postMessage.methodFullName shouldBe "slack_sdk.WebClient.chat_postMessage"
      }

      "resolve a dummy 'send' return value from sg.send" in {
          val List(postMessage) = cpg.identifier("response").l
          postMessage.typeFullName shouldBe "sendgrid.SendGridAPIClient.send.<returnValue>"
      }

  }

  "type recovery on class members" should {
      lazy val cpg = code("""
        |from flask_sqlalchemy import SQLAlchemy
        |
        |db = SQLAlchemy()
        |
        |class User(db.Model):
        |    __tablename__ = 'users'
        |
        |    id = db.Column(db.Integer, primary_key=True)
        |    firstname = db.Column(db.String)
        |    age = db.Column(db.Integer)
        |    address = db.Column(db.String(120))
        |
        |    def __repr__(self):
        |        return '<Task %r>' % self.id
        |
        |    @property
        |    def serialize(self):
        |        return {
        |            'id': self.id,
        |            'firstname': self.firstname,
        |            'age': self.age,
        |            'address': self.address
        |        }
        |""".stripMargin).cpg

      "resolve 'db' identifier types from import information" in {
          val List(clientAssignment, clientElseWhere) = cpg.identifier("db").take(2).l
          clientAssignment.typeFullName shouldBe "flask_sqlalchemy.SQLAlchemy"
          clientElseWhere.typeFullName shouldBe "flask_sqlalchemy.SQLAlchemy"
      }

      "resolve the 'SQLAlchemy' constructor in the module" in {
          val Some(client) = cpg.call("SQLAlchemy").headOption: @unchecked
          client.methodFullName shouldBe "flask_sqlalchemy.SQLAlchemy.__init__"
      }

      "resolve 'User' field types" in {
          val List(id, firstname, age, address) =
              cpg.identifier.nameExact("id", "firstname", "age", "address").l.takeRight(4)
          id.typeFullName shouldBe "flask_sqlalchemy.SQLAlchemy.Column"
          firstname.typeFullName shouldBe "flask_sqlalchemy.SQLAlchemy.Column"
          age.typeFullName shouldBe "flask_sqlalchemy.SQLAlchemy.Column"
          address.typeFullName shouldBe "flask_sqlalchemy.SQLAlchemy.Column"
      }

      "resolve the 'Column' constructor for a class member" in {
          val Some(columnConstructor) = cpg.call("Column").headOption: @unchecked
          columnConstructor.methodFullName shouldBe "flask_sqlalchemy.SQLAlchemy.Column.__init__"
      }

  }

  "recovering paths for built-in calls" should {
      lazy val cpg = code("""
        |print("Hello world")
        |max(1, 2)
        |
        |from foo import abs
        |
        |x = abs(-1)
        |""".stripMargin).cpg

      "resolve 'print' and 'max' calls" in {
          val Some(printCall) = cpg.call("print").headOption: @unchecked
          printCall.methodFullName shouldBe "__builtin.print"
          val Some(maxCall) = cpg.call("max").headOption: @unchecked
          maxCall.methodFullName shouldBe "__builtin.max"
      }

      "conservatively present either option when an imported function uses the same name as a builtin" in {
          val Some(absCall) = cpg.call("abs").headOption: @unchecked
          absCall.dynamicTypeHintFullName shouldBe Seq("foo.abs", "__builtin.abs")
      }

  }

  "recovering module members across modules" should {
      lazy val cpg = code(
        """
        |from flask_sqlalchemy import SQLAlchemy
        |
        |x = 1
        |y = "test"
        |db = SQLAlchemy()
        |""".stripMargin,
        "foo.py"
      ).moreCode(
        """
        |import foo
        |
        |z = foo.x
        |z = foo.y
        |
        |d = foo.db
        |
        |d.createTable()
        |
        |foo.db.deleteTable()
        |""".stripMargin,
        "bar.py"
      ).cpg

      "resolve correct imports via tag nodes" in {
          val List(foo1: UnknownMethod, foo2: UnknownTypeDecl) =
              cpg.file(".*foo.py").ast.isCall.where(
                _.referencedImports
              ).tag.toResolvedImport.toList: @unchecked
          foo1.fullName shouldBe "flask_sqlalchemy.SQLAlchemy.__init__"
          foo2.fullName shouldBe "flask_sqlalchemy.SQLAlchemy"
          val List(bar1: ResolvedTypeDecl, bar2: ResolvedMethod) =
              cpg.file(".*bar.py").ast.isCall.where(
                _.referencedImports
              ).tag.toResolvedImport.toList: @unchecked
          bar1.fullName shouldBe "foo"
          bar2.fullName shouldBe "foo"
      }

      "resolve 'x' and 'y' locally under foo.py" in {
          val Some(x) = cpg.file.name(".*foo.*").ast.isIdentifier.name("x").headOption: @unchecked
          x.typeFullName shouldBe "__builtin.int"
          val Some(y) = cpg.file.name(".*foo.*").ast.isIdentifier.name("y").headOption: @unchecked
          y.typeFullName shouldBe "__builtin.str"
      }

      "resolve 'foo.x' and 'foo.y' field access primitive types correctly" in {
          val List(z1, z2) = cpg.file
              .name(".*bar.*")
              .ast
              .isIdentifier
              .name("z")
              .l
          z1.typeFullName shouldBe "__builtin.str"
          z1.dynamicTypeHintFullName shouldBe Seq("__builtin.int")
          z2.typeFullName shouldBe "__builtin.str"
          z2.dynamicTypeHintFullName shouldBe Seq("__builtin.int")
      }

      "resolve 'foo.d' field access object types correctly" in {
          val Some(d) = cpg.file
              .name(".*bar.*")
              .ast
              .isIdentifier
              .name("d")
              .headOption: @unchecked
          d.typeFullName shouldBe "flask_sqlalchemy.SQLAlchemy"
          d.dynamicTypeHintFullName shouldBe Seq()
      }

      "resolve a 'createTable' call indirectly from 'foo.d' field access correctly" in {
          val List(d) = cpg.file
              .name(".*bar.*")
              .ast
              .isCall
              .name("createTable")
              .l
          d.methodFullName shouldBe "flask_sqlalchemy.SQLAlchemy.createTable"
          d.dynamicTypeHintFullName shouldBe Seq()
          d.callee(using NoResolve).isExternal.headOption shouldBe Some(true)
      }

      "resolve a 'deleteTable' call directly from 'foo.db' field access correctly" in {
          val List(d) = cpg.file
              .name(".*bar.*")
              .ast
              .isCall
              .name("deleteTable")
              .l

          d.methodFullName shouldBe "flask_sqlalchemy.SQLAlchemy.deleteTable"
          d.dynamicTypeHintFullName shouldBe Seq()
          d.callee(using NoResolve).isExternal.headOption shouldBe Some(true)
      }

  }

  "type recovery for a field imported as an individual component" should {
      lazy val cpg = code(
        """import app
        |from flask import jsonify
        |
        |def store():
        |    from app import db
        |    try:
        |        db.create_all()
        |        db.session.add(user)
        |        return jsonify({"success": True})
        |    except Exception as e:
        |        return 'There was an issue adding your task'
        |""".stripMargin,
        "UserController.py"
      ).moreCode(
        """
        |from flask_sqlalchemy import SQLAlchemy
        |
        |db = SQLAlchemy()
        |""".stripMargin,
        "app.py"
      ).cpg

      "resolve correct imports via tag nodes" in {
          val List(a: ResolvedTypeDecl, b: ResolvedMethod, c: UnknownImport, d: ResolvedMember) =
              cpg.file(".*UserController.py").ast.isCall.where(
                _.referencedImports
              ).tag.toResolvedImport.toList: @unchecked
          a.fullName shouldBe "app"
          b.fullName shouldBe "app"
          c.path shouldBe "flask.jsonify"
          d.basePath shouldBe "app"
          d.memberName shouldBe "db"

          val List(sqlAlchemyM: UnknownMethod, sqlAlchemyT: UnknownTypeDecl) =
              cpg.file(".*app.py").ast.isCall.where(
                _.referencedImports
              ).tag.toResolvedImport.toList: @unchecked
          sqlAlchemyM.fullName shouldBe "flask_sqlalchemy.SQLAlchemy.__init__"
          sqlAlchemyT.fullName shouldBe "flask_sqlalchemy.SQLAlchemy"
      }

      "be determined as a variable reference and have its type recovered correctly" in {
          cpg.identifier("db").map(_.typeFullName).toSet shouldBe Set(
            "flask_sqlalchemy.SQLAlchemy"
          )

          cpg
              .call("add")
              .where(_.parentBlock.ast.isIdentifier.typeFullName(
                "flask_sqlalchemy.SQLAlchemy"
              ))
              .where(_.parentBlock.ast.isFieldIdentifier.canonicalName("session"))
              .headOption
              .map(_.code) shouldBe Some("tmp0.add(user)")
      }

      "provide a dummy type to a member if the member type is not known" in {
          val Some(sessionTmpVar) = cpg.identifier("tmp0").headOption: @unchecked
          sessionTmpVar.typeFullName shouldBe "flask_sqlalchemy.SQLAlchemy.<member>(session)"

          val Some(addCall) = cpg
              .call("add")
              .headOption: @unchecked
          addCall.typeFullName shouldBe "ANY"
          addCall.methodFullName shouldBe "flask_sqlalchemy.SQLAlchemy.<member>(session).add"
          addCall.callee(using NoResolve).isExternal.headOption shouldBe Some(true)
      }

  }

  "assignment from a call to a method inside an imported module" should {
      lazy val cpg = code("""
        |import logging
        |log = logging.getLogger(__name__)
        |log.error("foo")
        |""".stripMargin).cpg

      "resolve correct imports via tag nodes" in {
          val List(logging: UnknownImport) =
              cpg.call.where(_.referencedImports).tag.toResolvedImport.toList: @unchecked
          logging.path shouldBe "logging"
      }

      "provide a dummy type" in {
          val Some(log) = cpg.identifier("log").headOption: @unchecked
          log.typeFullName shouldBe "logging.getLogger.<returnValue>"
          val List(errorCall) = cpg.call("error").l
          errorCall.methodFullName shouldBe "logging.getLogger.<returnValue>.error"
          val List(getLoggerCall) = cpg.call("getLogger").l
          getLoggerCall.methodFullName shouldBe "logging.getLogger"
      }
  }

  "a constructor call from a field access of an externally imported package" should {
      lazy val cpg = code("""
        |import urllib.error
        |import urllib.request
        |
        |req = urllib.request.Request(url=apiUrl, data=dataBytes, method='POST')
        |""".stripMargin).cpg

      "resolve correct imports via tag nodes" in {
          val List(error: UnknownImport, request: UnknownImport) =
              cpg.call.where(_.referencedImports).tag.toResolvedImport.toList: @unchecked
          error.path shouldBe "urllib.error"
          request.path shouldBe "urllib.request"
      }

      "reasonably determine the constructor type" in {
          val Some(tmp0) = cpg.identifier("tmp0").headOption: @unchecked
          tmp0.typeFullName shouldBe "urllib.request"
          val Some(requestCall) = cpg.call("Request").headOption: @unchecked
          requestCall.methodFullName shouldBe "urllib.request.Request.__init__"
      }
  }

  "a method call inherited from a super class should be recovered" should {
      lazy val cpg = code(
        """from pymongo import MongoClient
        |from django.conf import settings
        |
        |
        |class MongoConnection(object):
        |    def __init__(self):
        |        DATABASES = settings.DATABASES
        |        self.client = MongoClient(
        |            host=[DATABASES['MONGO']['HOST']],
        |            username=DATABASES['MONGO']['USERNAME'],
        |            password=DATABASES['MONGO']['PASSWORD'],
        |            authSource=DATABASES['MONGO']['AUTH_DATABASE']
        |        )
        |        self.db = self.client[DATABASES['MONGO']['DATABASE']]
        |        self.collection = None
        |
        |    def get_collection(self, name):
        |        self.collection = self.db[name]
        |""".stripMargin,
        "MongoConnection.py"
      ).moreCode(
        """
        |from MongoConnection import MongoConnection
        |
        |class InstallationsDAO(MongoConnection):
        |    def __init__(self):
        |        super(InstallationsDAO, self).__init__()
        |        self.get_collection("installations")
        |
        |    def getCustomerId(self, installationId):
        |        res = self.collection.find_one({'_id': installationId})
        |        if res is None:
        |            return None
        |        return dict(res).get("customerId", None)
        |""".stripMargin,
        "InstallationDao.py"
      ).moreCode(
        """
        |# dummy file to trigger isExternal = false on methods that are imported from here
        |""".stripMargin,
        "pymongo.py"
      ).cpg

      "resolve correct imports via tag nodes" in {
          val List(
            a: ResolvedTypeDecl,
            b: ResolvedMethod,
            c: UnknownMethod,
            d: UnknownTypeDecl,
            e: UnknownImport
          ) =
              cpg.call.where(_.referencedImports).tag.toResolvedImport.toList: @unchecked

          a.fullName shouldBe "MongoConnection.MongoConnection"
          b.fullName shouldBe "MongoConnection.MongoConnection.__init__"
          c.fullName shouldBe "pymongo.MongoClient.__init__"
          d.fullName shouldBe "pymongo.MongoClient"
          e.path shouldBe "django.conf.settings"
      }

      "recover a potential type for `self.collection` using the assignment at `get_collection` as a type hint" in {
          val Some(selfFindFound) = cpg.typeDecl(".*InstallationsDAO.*").ast.isCall.name(
            "find_one"
          ).headOption: @unchecked
          selfFindFound.dynamicTypeHintFullName shouldBe Seq(
            "__builtin.None.find_one",
            "pymongo.MongoClient.__init__.<indexAccess>.<indexAccess>.find_one"
          )
      }

      "correctly determine that, despite being unable to resolve the correct method full name, that it is an internal method" in {
          val Some(selfFindFound) = cpg.typeDecl(".*InstallationsDAO.*").ast.isCall.name(
            "find_one"
          ).headOption: @unchecked
          selfFindFound.callee.isExternal.toSeq shouldBe Seq(true, true, true)
      }
  }

  "a recursive field access based call type" should {
      lazy val cpg = code(
        """
        |from flask import Flask, render_template
        |from flask_pymongo import PyMongo
        |
        |# Instance of Flask
        |app = Flask(__name__)
        |mongo = PyMongo(app)
        |
        |
        |@app.route('/')
        |@app.route("/bikes")
        |def bike():
        |    bikes = mongo.db.bikes.find()
        |    return render_template("index.html", bikes=bikes)
        |""".stripMargin,
        "app.py"
      )

      "manage to create a correct chain of dummy field accesses before the call" in {
          val Some(bikeFind) = cpg.call.name("find").headOption: @unchecked
          bikeFind.methodFullName shouldBe "flask_pymongo.PyMongo.<member>(db).<member>(bikes).find"
      }
  }

  "a call from an import where the import acts as a module" should {
      lazy val cpg = code(
        """import os
        |import datadog
        |
        |# Initialize the Datadog client
        |options = {
        |    'api_key': os.environ.get('DD_API_KEY'),
        |    'app_key': os.environ.get('DD_APP_KEY')
        |}
        |
        |datadog.initialize(**options)
        |""".stripMargin,
        "app.py"
      )

      "recover the import as an identifier and not directly as a call" in {
          val Some(initCall) = cpg.call.name("initialize").headOption: @unchecked
          initCall.methodFullName shouldBe "datadog.initialize"
      }
  }

  "a call made from within a call invocation" should {
      lazy val cpg = code("""
        |from __future__ import unicode_literals
        |
        |from django.db import migrations, models
        |
        |
        |class Migration(migrations.Migration):
        |
        |    dependencies = [
        |        ('music', '0006_auto_20160325_1236'),
        |    ]
        |
        |    operations = [
        |        migrations.AddField(
        |            model_name='album',
        |            name='is_favorite',
        |            field=models.BooleanField(default=False),
        |        ),
        |    ]
        |""".stripMargin)

      "recover its full name successfully" in {
          val Some(addFieldConstructor) = cpg.call.name("AddField").headOption: @unchecked
          addFieldConstructor.methodFullName shouldBe "django.db.migrations.AddField.__init__"
          val Some(booleanFieldConstructor) = cpg.call.name("BooleanField").headOption: @unchecked
          booleanFieldConstructor.methodFullName shouldBe "django.db.models.BooleanField.__init__"
      }
  }

  "a call made via an import from a directory" should {
      lazy val cpg = code("""
        |from data import db_session
        |
        |def foo():
        |   db_sess = db_session.create_session()
        |   x = db_sess.query(foo, bar)
        |""".stripMargin)
          .moreCode(
            """
          |from sqlalchemy.orm import Session
          |
          |def create_session() -> Session:
          |   global __factory
          |   return __factory()
          |""".stripMargin,
            "data.db_session.py"
          )

      "resolve correct imports via tag nodes" in {
          val List(
            sessionT: ResolvedTypeDecl,
            sessionM: ResolvedMethod,
            sqlSessionM: UnknownMethod,
            sqlSessionT: UnknownTypeDecl
          ) = cpg.call.where(_.referencedImports).tag.toResolvedImport.toList: @unchecked
          sessionT.fullName shouldBe "data.db_session"
          sessionM.fullName shouldBe "data.db_session"
          sqlSessionM.fullName shouldBe "sqlalchemy.orm.Session.__init__"
          sqlSessionT.fullName shouldBe "sqlalchemy.orm.Session"
      }

      "recover its full name successfully" in {
          val List(methodFullName) = cpg.call("query").methodFullName.l
          methodFullName shouldBe "sqlalchemy.orm.Session.query"
      }

      "reflect these types as under the type full name" in {
          val Some(ret) = cpg.method("create_session").methodReturn.headOption: @unchecked
          ret.typeFullName shouldBe "sqlalchemy.orm.Session"
      }
  }

  "recover a method ref from a field identifier" should {
      lazy val cpg = code(
        """
        |from django.conf.urls import url
        |
        |from student import views
        |
        |urlpatterns = [
        |    url(r'^addStudent/$', views.add_student)
        |]
        |""".stripMargin,
        "urls.py"
      ).moreCode(
        """
        |def add_student():
        | pass
        |""".stripMargin,
        "student.views.py"
      )

      "recover the method full name related" in {
          val Some(methodRef) = cpg.methodRef.code("views.add_student").headOption: @unchecked
          methodRef.methodFullName shouldBe "student.views.add_student"
          methodRef.typeFullName shouldBe "<empty>"
      }
  }

  "a type hint on a parameter" should {
      lazy val cpg = code("""
        |import sqlalchemy.orm as orm
        |
        |async def get_user_by_email(email: str, db: orm.Session):
        |   return db.query(user_models.User).filter(user_models.User.email == email).first()
        |""".stripMargin)

      "be sufficient to resolve method full names at calls" in {
          val List(call) = cpg.call("query").l
          call.methodFullName shouldBe "sqlalchemy.orm.Session.query"
      }

  }

  "recover a member call from a reference to an imported global variable" should {
      lazy val cpg = code(
        """from api import db
        |
        |class UserModel(db.Model):
        |
        |   def save(self):
        |        try:
        |            db.session.add(self)
        |            db.session.commit()
        |        except IntegrityError:
        |            print(f"User with username={self.username} already exist")
        |            db.session.rollback()
        |""".stripMargin,
        "api.models.user.py"
      ).moreCode(
        """from flask_sqlalchemy import SQLAlchemy
        |
        |app = Flask(__name__, static_folder=Config.UPLOAD_FOLDER)
        |
        |db = SQLAlchemy(app)
        |""".stripMargin,
        "api.__init__.py"
      )

      "resolve correct imports via tag nodes" in {
          val List(sqlSessionM: UnknownMethod, sqlSessionT: UnknownTypeDecl, db: ResolvedMember) =
              cpg.call.where(_.referencedImports).tag.toResolvedImport.toList: @unchecked
          sqlSessionM.fullName shouldBe "flask_sqlalchemy.SQLAlchemy.__init__"
          sqlSessionT.fullName shouldBe "flask_sqlalchemy.SQLAlchemy"
          db.basePath shouldBe "api.__init__"
          db.memberName shouldBe "db"
      }

      "recover a call to `add`" in {
          val Some(addCall) = cpg.call("add").headOption: @unchecked
          addCall.methodFullName shouldBe "flask_sqlalchemy.SQLAlchemy.<member>(session).add"
      }
  }

  "handle a wrapper function with the same name as an imported function" should {
      lazy val cpg = code("""
        |import requests
        |
        |class Client:
        |    access_token: str = None
        |    def post(self, uuid: str, account_id: str, endpoint: str = "results"):
        |        if not self.access_token:
        |            self.authenticate()
        |
        |        response = requests.post(
        |          url=f"https://{account_id}.rest.marketingcloudapis.com/data/v1/async/{uuid}/{endpoint}",
        |            headers={
        |                "Authorization": self.auth_header(),
        |                "Content-Type": "application/json",
        |            },
        |        )
        |        return response
        |""".stripMargin)

      "recover the child function `post` path correctly via receiver" in {
          val Some(postCallReceiver) = cpg.identifier("requests").headOption: @unchecked
          postCallReceiver.typeFullName shouldBe "requests"
          val Some(postCall) = cpg.call("post").headOption: @unchecked
          postCall.methodFullName shouldBe "requests.post"
      }
  }

  "handle a call from parameter with a type hint" should {
      lazy val cpg = code("""
        |import models.user as user_models
        |import sqlalchemy.orm as orm
        |
        |async def get_user_by_email(email: str, db: orm.Session):
        |    return db.query(user_models.User).filter(user_models.User.email == email).first()
        |""".stripMargin)

      "with the correct identifier and call types" in {
          val Some(postCallReceiver) = cpg.identifier("db").headOption: @unchecked
          postCallReceiver.typeFullName shouldBe "sqlalchemy.orm.Session"
          val Some(postCall) = cpg.call("query").headOption: @unchecked
          postCall.methodFullName shouldBe "sqlalchemy.orm.Session.query"
      }

      "reflect these types as under the type full name" in {
          val List(p1, p2) = cpg.method("get_user_by_email").parameter.l
          p1.typeFullName shouldBe "__builtin.str"
          p2.typeFullName shouldBe "sqlalchemy.orm.Session"
      }
  }

  "Import statement with method ref sample one" in {
      val controller =
          """
        |from django.contrib import admin
        |from django.urls import path
        |from django.conf.urls import url
        |from student import views
        |
        |urlpatterns = [
        |    url(r'allPage', views.all_page)
        |]
        |""".stripMargin
      val views =
          """
        |def all_page(request):
        |	print("All pages")
        |""".stripMargin
      val cpg = code("print('Hello, world!')")
          .moreCode(controller, "controller.urls.py")
          .moreCode(views, "student.views.py")

      val Some(allPageRef) = cpg.call.methodFullName(
        "django.*[.](path|url)"
      ).argument.isMethodRef.headOption: @unchecked
      allPageRef.methodFullName shouldBe "student.views.all_page"
      allPageRef.code shouldBe "views.all_page"
  }

  "Import statement with method ref sample two" in {
      val controller =
          """
        |from django.contrib import admin
        |from django.urls import path
        |from django.conf.urls import url
        |from .import views
        |
        |urlpatterns = [
        |    url(r'allPage', views.all_page)
        |]
        |""".stripMargin
      val views =
          """
        |def all_page(request):
        |	print("All pages")
        |""".stripMargin
      val cpg = code(controller, "urls.py")
          .moreCode(views, "views.py")

      val Some(allPageRef) = cpg.call.methodFullName(
        "django.*[.](path|url)"
      ).argument.isMethodRef.headOption: @unchecked
      allPageRef.methodFullName shouldBe "views.all_page"
      allPageRef.code shouldBe "views.all_page"
  }

  // Written as a real `controller/` directory rather than the old `controller.urls.py` -
  // a file name with dots is not an importable module in Python at all, and the file-mode
  // arm that used to make that spelling behave like a package went away with the mode.
  // The construct under test - relative `from . import views` - is unchanged.
  "Import statement with method ref sample three" in {
      val controller =
          """
        |from django.contrib import admin
        |from django.urls import path
        |from django.conf.urls import url
        |from .import views
        |
        |urlpatterns = [
        |    url(r'allPage', views.all_page)
        |]
        |""".stripMargin
      val views =
          """
        |def all_page(request):
        |	print("All pages")
        |""".stripMargin
      val cpg = code(controller, "controller/urls.py")
          .moreCode(views, "controller/views.py")

      val Some(allPageRef) = cpg.call.methodFullName(
        "django.*[.](path|url)"
      ).argument.isMethodRef.headOption: @unchecked
      allPageRef.methodFullName shouldBe "controller.views.all_page"
      allPageRef.code shouldBe "views.all_page"
  }

  "Import statement with method ref sample four" in {
      val controller =
          """
        |from django.contrib import admin
        |from django.urls import path
        |from django.conf.urls import url
        |from .views import all_page
        |
        |urlpatterns = [
        |    url(r'allPage', all_page)
        |]
        |""".stripMargin
      val views =
          """
        |def all_page(request):
        |	print("All pages")
        |""".stripMargin
      val cpg = code(controller, "controller/urls.py")
          .moreCode(views, "controller/views.py")

      val Some(allPageRef) = cpg.call.methodFullName(
        "django.*[.](path|url)"
      ).argument.isMethodRef.headOption: @unchecked
      allPageRef.methodFullName shouldBe "controller.views.all_page"
      allPageRef.code shouldBe "all_page"
  }

  "Import statement with method ref sample five" in {
      val controller =
          """
        |from django.contrib import admin
        |from django.urls import path
        |from django.conf.urls import url
        |from student.views import all_page
        |
        |urlpatterns = [
        |    url(r'allPage', all_page)
        |]
        |""".stripMargin
      val views =
          """
        |def all_page(request):
        |	print("All pages")
        |""".stripMargin
      val cpg = code(controller, "controller.urls.py")
          .moreCode(views, "student.views.py")

      val Some(allPageRef) = cpg.call.methodFullName(
        "django.*[.](path|url)"
      ).argument.isMethodRef.headOption: @unchecked
      allPageRef.methodFullName shouldBe "student.views.all_page"
      allPageRef.code shouldBe "all_page"
  }

  "Import statement with method ref sample six" in {
      val controller =
          """
        |from django.urls import path
        |from authy.views import PasswordChange
        |
        |urlpatterns = [
        |   path('changepassword/', PasswordChange, name='change_password')
        |]
        |""".stripMargin
      val views =
          """from django.contrib.auth.decorators import login_required
        |
        |@login_required
        |def PasswordChange(request):
        |    print("All pages")
        |
        |""".stripMargin
      val cpg = code(controller, "controller.urls.py")
          .moreCode(views, "authy.views.py")

      val Some(allPageRef) = cpg.call.methodFullName(
        "django.*[.](path|url)"
      ).argument.isMethodRef.headOption: @unchecked
      allPageRef.methodFullName shouldBe "authy.views.PasswordChange"
      allPageRef.code shouldBe "PasswordChange"
  }

  "Classes extended by function calls" should {
      lazy val cpg = code("""
        |from sqlalchemy.ext.declarative import declarative_base
        |
        |class Foo(declarative_base(metadata=metadata)):
        |    pass
        |
        |x = declarative_base(metadata=metadata)
        |class Bar(x):
        |    pass
        |
        |""".stripMargin)

      "present an appropriate dummy type for direct call returns" in {
          cpg.typeDecl("Foo").inheritsFromTypeFullName.l shouldBe List(
            "sqlalchemy.ext.declarative.declarative_base.<returnValue>"
          )
      }

      "present an appropriate dummy type for call results held by identifiers" in {
          cpg.typeDecl("Bar").inheritsFromTypeFullName.l shouldBe List(
            "sqlalchemy.ext.declarative.declarative_base.<returnValue>"
          )
      }
  }

  "Class methods with the `@classmethod` decorator" should {
      lazy val cpg = code("""
        |class MyClass:
        |
        |    @classmethod
        |    def class_method(cls):
        |        print("Class Method ", cls)
        |
        |""".stripMargin)

      "resolve the cls variable" in {
          cpg.method("class_method").parameter.name("cls").typeFullName.headOption shouldBe Some(
            "Test0.MyClass"
          )
      }
  }

  "calls from imported class fields" should {
      lazy val cpg = code(
        """
        |from .models import Profile
        |
        |def profile(request):
        |    profile = Profile.objects.filter(user=request.user).order_by('-id')[0]
        |""".stripMargin,
        "views.py"
      ).moreCode(
        """
        |from django.db import models
        |
        |class Profile(models.Model):
        |    user = models.CharField(max_length=20)
        |    name = models.CharField(max_length=50)
        |""".stripMargin,
        "models.py"
      )

      "resolve correct imports via tag nodes" in {
          val List(
            djangoModels: UnknownImport,
            profileT: ResolvedTypeDecl,
            profileM: ResolvedMethod
          ) =
              cpg.call.where(_.referencedImports).tag.toResolvedImport.toList: @unchecked
          djangoModels.path shouldBe "django.db.models"
          profileT.fullName shouldBe "models.Profile"
          profileM.fullName shouldBe "models.Profile.__init__"
      }

      "resolve the `filter` call" in {
          val Some(call) = cpg.call.nameExact("filter").headOption: @unchecked
          call.methodFullName shouldBe "models.Profile.<member>(objects).filter"
      }

  }

  "Recovered values that are returned in methods" should {
      lazy val cpg = code(
        """
        |class Connector:
        |
        |	botoClient = boto("s3")
        |
        |	def makeDbCall():
        |		pass
        |
        |	def getBotoClient(self):
        |		return self.botoClient
        |
        |""".stripMargin,
        "lib.connector.py"
      ).moreCode(
        """
        |from lib.connector import Connector
        |
        |class Impl:
        |
        |	c = Connector()
        |	c.getBotoClient().getS3Object()
        |""".stripMargin,
        "impl.py"
      )

      "resolve correct imports via tag nodes" in {
          val List(connectorT: ResolvedTypeDecl, connectorM: ResolvedMethod) =
              cpg.call.where(_.referencedImports).tag.toResolvedImport.toList: @unchecked
          connectorT.fullName shouldBe "lib.connector.Connector"
          connectorM.fullName shouldBe "lib.connector.Connector.__init__"
      }

      "be able to use field accesses as type hints" in {
          val Some(c) = cpg.identifier("c").headOption: @unchecked
          c.typeFullName shouldBe "lib.connector.Connector"
          val Some(getBotoClient) = cpg.call.nameExact("getBotoClient").headOption: @unchecked
          getBotoClient.methodFullName shouldBe "lib.connector.Connector.getBotoClient"
          val Some(getS3Object) = cpg.call.nameExact("getS3Object").headOption: @unchecked
          getS3Object.methodFullName shouldBe "boto.<returnValue>.getS3Object"
      }
  }

  "Static class calls from imported types" should {
      lazy val cpg = code(
        """
        |from db.redis import RedisDB
        |
        |class FooServer():
        |
        | async def callback(self):
        |   await RedisDB.instance().set("apiuserscache", json.dumps(resp), expires=1800)
        |
        |   redis = await RedisDB.instance().get_redis()
        |   await redis.publish_json(123, {})
        |""".stripMargin,
        "fooserver.py"
      ).moreCode(
        """
        |import aioredis
        |
        |class RedisDB(object):
        |    _instance = None
        |
        |    @classmethod
        |    def instance(cls) -> 'RedisDB':
        |        if cls._instance is None:
        |            cls._instance = cls.__new__(cls)
        |            cls.redis = None
        |        return cls._instance
        |
        |    @classmethod
        |    async def get_redis(cls) -> aioredis.Redis:
        |       pass
        |
        |    async def set(self, key: str, value: str, expires: int = 0):
        |        redis = await self.get_redis()
        |        await redis.set(key, value, expire=expires)
        |""".stripMargin,
        "db.redis.py"
      )

      "assert the method properties in RedisDB, especially quoted type hints" in {
          val Some(redisDB) =
              cpg.typeDecl.nameExact("RedisDB").method.nameExact("<body>").headOption: @unchecked
          val List(instanceM, getRedisM, setM) =
              redisDB.astOut.isMethod.nameExact("instance", "get_redis", "set").l

          instanceM.methodReturn.typeFullName shouldBe "db.redis.RedisDB"
          getRedisM.methodReturn.typeFullName shouldBe "aioredis.Redis"
          setM.methodReturn.typeFullName shouldBe "ANY"
      }

      "be able to generate an appropriate dummy value" in {
          val Some(redisSet) = cpg.call.code(".*set.*apiuserscache.*").headOption: @unchecked
          redisSet.methodFullName shouldBe "db.redis.RedisDB.set"
      }

      "be able to handle a simple call off an alias" in {
          val Some(redisGet) = cpg.call.nameExact("publish_json").headOption: @unchecked
          redisGet.methodFullName shouldBe "db.redis.RedisDB.get_redis.publish_json"
      }
  }

  "Type instantiation via caller" should {
      lazy val cpg = code(
        """
        |from oauth2 import Token
        |
        |class FlickrAuth(ConsumerBasedOAuth):
        |   def access_token(token):
        |       response = self.fetch_response(request)
        |       token = Token.from_string(response)
        |""".stripMargin,
        "social_auth.backends.contrib.flickr.py"
      )
          .moreCode(
            """
        |class Token(object):
        |
        |    key = None
        |    secret = None
        |
        |    def __init__(self, key, secret):
        |        self.key = key
        |        self.secret = secret
        |
        |    @staticmethod
        |    def from_string(s):
        |        if not len(s):
        |            raise ValueError("Invalid parameter string.")
        |
        |        params = parse_qs(u(s), keep_blank_values=False)
        |        if not len(params):
        |            raise ValueError("Invalid parameter string.")
        |
        |        try:
        |            key = params['oauth_token'][0]
        |        except Exception:
        |            raise ValueError("'oauth_token' not found in OAuth request.")
        |
        |        try:
        |            secret = params['oauth_token_secret'][0]
        |        except Exception:
        |            raise ValueError("'oauth_token_secret' not found in "
        |                "OAuth request.")
        |
        |        token = Token(key, secret)
        |        return token
        |""".stripMargin,
            "oauth2.__init__.py"
          )

      "instantiate the return value correctly under `from_string`" in {
          val Some(token) =
              cpg.method("from_string").ast.isIdentifier.nameExact("token").headOption: @unchecked
          token.typeFullName shouldBe "oauth2.__init__.Token"
          val Some(fromString) = cpg.method("from_string").methodReturn.headOption: @unchecked
          fromString.typeFullName shouldBe "oauth2.__init__.Token"
      }

      "propagate the type in the return value" in {
          val Some(token) = cpg.method("access_token").ast.isIdentifier.nameExact(
            "token"
          ).headOption: @unchecked
          token.typeFullName shouldBe "oauth2.__init__.Token"
      }

  }

  "Imports from two module neighbours" should {

      lazy val cpg = code(
        """
        |from fastapi import FastAPI
        |import itemsrouter
        |app = FastAPI()
        |app.include_router(
        |    itemsrouter.router,
        |    prefix="/items",
        |    tags=["items"],
        |    responses={404: {"description": "Not found"}},
        |)
        |""".stripMargin,
        "code/main.py"
      ).moreCode(
        """
        |from fastapi import APIRouter
        |
        |router = APIRouter()
        |fake_items_db = {"plumbus": {"name": "Plumbus"}, "gun": {"name": "Portal Gun"}}
        |@router.get("/")
        |async def read_items():
        |    return fake_items_db
        |
        |""".stripMargin,
        "code/itemsrouter.py"
      )

      // The fixture was `code.main.py`/`code.itemsrouter.py` - dots in the FILE NAME, which is
      // not an importable Python module at all and only ever stood in for a directory. Under
      // dotted names that spelling has no module prefix to preserve, so the test is written as
      // the layout it was always describing: a real `code/` package neighbourhood, where
      // `code.itemsrouter` is exactly what CPython would call the module.
      "preserve the filename path relative to the root and not themselves" in {
          val itemsrouter = cpg.identifier.where(_.typeFullName(".*itemsrouter")).l
          itemsrouter.map(_.typeFullName).distinct.foreach(t =>
              t shouldBe "code.itemsrouter"
          )
      }

      "correctly infer the `fastapi` types" in {
          cpg.identifier("fastapi").forall(
            _.typeFullName == "fastapi.APIRouter"
          ) shouldBe true
          cpg.identifier("app").forall(
            _.typeFullName == "fastapi.FastAPI"
          ) shouldBe true
      }

  }

  "assignment to non-chained index access of an imported member method call" should {
      val cpg = code(
        """
              |import foo
              |x = foo.bar()
              |y = x[0]
              |""".stripMargin
      )

      "provide meaningful typeFullName for the target of the first assignment" in {
          cpg.assignment.target.isIdentifier.name("x").l match
            case List(x) => x.typeFullName shouldBe "foo.bar.<returnValue>"
            case result  => fail(s"Expected single assignment to x, but got $result")
      }

      "provide meaningful typeFullName for the target of the second assignment" in {
          cpg.assignment.target.isIdentifier.name("y").l match
            case List(y) =>
                y.typeFullName shouldBe "foo.bar.<returnValue>.<indexAccess>"
            case result => fail(s"Expected single assignment to y, but got $result")
      }
  }

  "assignment to chained index access of an imported member method call" should {
      val cpg = code(
        """
              |import foo
              |y = foo.bar()[0]
              |""".stripMargin
      )

      "provide meaningful typeFullName for the target of the assignment" in {
          cpg.assignment.target.isIdentifier.name("y").l match
            case List(y) => y.typeFullName shouldBe "foo.bar.<indexAccess>"
            case result  => fail(s"Expected single assignment to y, but got $result")
      }
  }

  "assignment to interspersed index access with imported method calls" should {
      val cpg = code(
        """
              |import foo
              |x = foo.bar()[0].baz()
              |""".stripMargin
      )

      "have correct methodFullName for `bar`" in {
          cpg.call.name("bar").l match
            case List(bar) => bar.methodFullName shouldBe "foo.bar"
            case result    => fail(s"Expected single call to bar, but got $result")
      }

      "have correct methodFullName for `baz`" in {
          cpg.call.name("baz").l match
            case List(baz) =>
                baz.methodFullName shouldBe "foo.bar.<indexAccess>.baz"
            case result => fail(s"Expected single call to baz, but got $result")
      }

      // TODO: Missing the last <returnValue>. Needs to take into account the lowering of consecutive
      //  field accesses into three-address code blocks.
      "provide meaningful typeFullName for the target of the assignment" ignore {
          cpg.assignment.target.isIdentifier.name("x").l match
            case List(x) => x.typeFullName shouldBe "foo.bar.<indexAccess>.baz"
            case result  => fail(s"Expected single assignment to x, but got $result")
      }
  }

  "call to interspersed index access with imported method calls and constructors" should {
      val cpg = code(
        """
              |import boto3
              |sqs = boto3.resource('sqs')
              |queue = sqs.Queue('url')
              |queue.receive_messages()[0].delete()
              |""".stripMargin
      )

      "have correct methodFullName for `delete`" in {
          cpg.call.name("delete").l match
            case List(delete) =>
                delete.methodFullName shouldBe "boto3.resource.<returnValue>.Queue.receive_messages.<indexAccess>.delete"
            case result => fail(s"Expected single call to delete, but got $result")
      }

      "have correct methodFullName for `resource`" in {
          cpg.call.name("resource").l match
            case List(resource) => resource.methodFullName shouldBe "boto3.resource"
            case result         => fail(s"Expected single call to resource, but got $result")
      }

      "have correct methodFullName for `receive_messages`" in {
          cpg.call.name("receive_messages").l match
            case List(recv) =>
                recv.methodFullName shouldBe "boto3.resource.<returnValue>.Queue.receive_messages"
            case result => fail(s"Expected single call to receive_messages, but got $result")
      }

      "provide meaningful typeFullName for `sqs`" in {
          cpg.assignment.target.isIdentifier.name("sqs").l match
            case List(sqs) =>
                sqs.typeFullName shouldBe "boto3.resource.<returnValue>"
            case result => fail(s"Expected single assignment to sqs, but got $result")
      }

      "provide meaningful typeFullName for `queue`" in {
          cpg.assignment.target.isIdentifier.name("queue").l match
            case List(queue) =>
                queue.typeFullName shouldBe "boto3.resource.<returnValue>.Queue"
            case result => fail(s"Expected single assignment to queue, but got $result")
      }
  }

  "`__builtin.print` call with an external non-imported call result variable for argument" should {
      val cpg = code(
        """
              |a = foo(10)
              |print(a)
              |""".stripMargin
      )
      "have correct methodFullName for `print`" in {
          cpg.call("print").l match
            case List(printCall) => printCall.methodFullName shouldBe "__builtin.print"
            case result          => fail(s"Expected single print call but got $result")
      }
      "have correct methodFullName for `foo`" in {
          cpg.call("foo").l match
            case List(fooCall) => fooCall.methodFullName shouldBe "foo"
            case result        => fail(s"Expected single foo call but got $result")
      }

      "provide meaningful typeFullName for the target of assignment" in {
          cpg.assignment.target.isIdentifier.name("a").l match
            case List(a) => a.typeFullName shouldBe "foo.<returnValue>"
            case result  => fail(s"Expected single assignment to a, but got $result")
      }
  }

  "assignment to non imported call with int variable for argument" should {
      val cpg = code(
        """
              |a = 10
              |b = foo(a)
              |""".stripMargin
      )

      "have correct methodFullName for `foo`" in {
          cpg.call("foo").l match
            case List(fooCall) => fooCall.methodFullName shouldBe "__builtin.int.foo"
            case result        => fail(s"Expected single foo call but got $result")
      }

      "provide meaningful typeFullName for the target of the assignment" in {
          cpg.assignment.target.isIdentifier.name("b").l match
            case List(b) => b.typeFullName shouldBe "foo.<returnValue>"
            case result  => fail(s"Expected single assignment to b, but got $result")
      }
  }

  "generic collection type hint and index access recovery" should {
      val cpg = code(
        """
              |x: list[int] = [1, 2, 3]
              |y = x[0]
              |
              |d: dict[str, float] = {}
              |z = d["key"]
              |""".stripMargin
      )

      "recover the types of the generic collections and their element index accesses" in {
          cpg.identifier("x").typeFullName.headOption shouldBe Some("__builtin.list[__builtin.int]")
          cpg.identifier("y").typeFullName.headOption shouldBe Some("__builtin.int")
          cpg.identifier("d").typeFullName.headOption shouldBe Some(
            "__builtin.dict[__builtin.str, __builtin.float]"
          )
          cpg.identifier("z").typeFullName.headOption shouldBe Some("__builtin.float")
      }
  }
end TypeRecoveryPassTests
