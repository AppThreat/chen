package io.appthreat.ruby2atom.datastructures

import better.files.File
import io.appthreat.x2cpg.Defines as XDefines
import io.appthreat.x2cpg.datastructures.{
    FieldLike,
    MethodLike,
    ProgramSummary,
    StubbedType,
    TypeLike
}
import io.appthreat.x2cpg.typestub.{TypeStubMetaData, TypeStubUtil}
import io.appthreat.ruby2atom.passes.Defines
import upickle.default.*

import java.io.{ByteArrayInputStream, InputStream}
import java.util.zip.ZipInputStream
import scala.annotation.targetName
import scala.collection.mutable
import scala.collection.mutable.ListBuffer
import scala.util.{Failure, Success, Try}

type NamespaceToTypeMap = mutable.Map[String, mutable.Set[RubyType]]

class RubyProgramSummary(
  initialNamespaceMap: NamespaceToTypeMap = mutable.Map.empty,
  initialPathMap: NamespaceToTypeMap = mutable.Map.empty,
  initialConstants: collection.Set[String] = Set.empty,
  initialAncestors: collection.Map[String, List[String]] = Map.empty,
  initialSolidConstants: collection.Set[String] = Set.empty
) extends ProgramSummary[RubyType, RubyMethod, RubyField]:

  override val namespaceToType: NamespaceToTypeMap = initialNamespaceMap
  val pathToType: NamespaceToTypeMap               = initialPathMap

  /** The constants the project defines, as dotted paths (`Outer.Inner`): every class and module
    * with each of its prefixes and also under the name it is written with inside its module, every
    * constant assignment, and the names Rails autoloading implies for the files under `app/` and
    * `lib/`. A reference that resolves to one of these is not a use of a dependency.
    */
  val definedConstants: collection.Set[String] = initialConstants

  /** The subset of [[definedConstants]] the project really defines: a class, a module whose body
    * holds more than nested classes and modules, a constant assignment, or the constant a file's
    * path names. The rest only nest things in a namespace, which a gem may own: `module Rails;
    * class Foo` reopens the gem's `Rails`. A namespace of that kind has no methods and no constants
    * of its own, so `Rails.logger` and `Rails::Missing` reach the gem.
    */
  val solidConstants: collection.Set[String] = initialSolidConstants

  /** The written ancestors (superclass, `include` and `prepend` arguments) of each class or module
    * the project declares, keyed by its dotted path. Used to look a constant up through the
    * ancestors of the innermost class, as Ruby does.
    */
  val ancestors: collection.Map[String, List[String]] = initialAncestors

  @targetName("appendAll")
  def ++=(other: RubyProgramSummary): RubyProgramSummary =
      RubyProgramSummary(
        ProgramSummary.merge(this.namespaceToType, other.namespaceToType),
        ProgramSummary.merge(this.pathToType, other.pathToType),
        this.definedConstants ++ other.definedConstants,
        this.ancestors ++ other.ancestors,
        this.solidConstants ++ other.solidConstants
      )
end RubyProgramSummary

object RubyProgramSummary:

  def BuiltinTypes(implicit typeStubMetaData: TypeStubMetaData): NamespaceToTypeMap =
    val typeStubDir = File(typeStubMetaData.packagePath)
    if !typeStubDir.exists || !typeStubDir.isDirectory then
      mutable.Map.empty
    else if typeStubMetaData.useTypeStubs then
      mpkZipToInitialMapping(mergeBuiltinMpkZip) match
        case Failure(exception) => mutable.Map.empty
        case Success(mapping)   => mapping
    else
      mutable.Map.empty

  private def mpkZipToInitialMapping(inputStream: InputStream): Try[NamespaceToTypeMap] =
      Try(readBinary[NamespaceToTypeMap](inputStream.readAllBytes()))

  private def mergeBuiltinMpkZip(implicit typeStubMetaData: TypeStubMetaData): InputStream =
    val classLoader = getClass.getClassLoader
    val typeStubDir = TypeStubUtil.typeStubDir

    val typeStubFiles: Seq[File] =
        typeStubDir
            .walk()
            .filter(f =>
                f.isRegularFile && f.name.startsWith("rubysrc") && f.`extension`.contains(".zip")
            )
            .toSeq

    if typeStubFiles.isEmpty then
      InputStream.nullInputStream()
    else
      val mergedMpksObj = ListBuffer[collection.mutable.Map[String, Set[RubyStubbedType]]]()
      typeStubFiles.foreach { f =>
          f.fileInputStream { fis =>
            val zis = new ZipInputStream(fis)

            LazyList.continually(zis.getNextEntry).takeWhile(_ != null).foreach { file =>
              val mpkObj =
                  upickle.default.readBinary[collection.mutable.Map[
                    String,
                    Set[RubyStubbedType]
                  ]](zis.readAllBytes())
              mergedMpksObj.addOne(mpkObj)
            }
          }
      }

      val mergedMpks = mergedMpksObj
          .reduceOption((prev, curr) =>
            curr.keys.foreach(key =>
                prev.updateWith(key) {
                    case Some(x) =>
                        Option(x ++ curr(key))
                    case None =>
                        Option(curr(key))
                }
            )
            prev
          )
          .getOrElse(collection.mutable.Map[String, Set[RubyStubbedType]]())

      new ByteArrayInputStream(upickle.default.writeBinary(mergedMpks))
    end if
  end mergeBuiltinMpkZip
end RubyProgramSummary

case class RubyMethod(
  name: String,
  parameterTypes: List[(String, String)],
  returnType: String,
  baseTypeFullName: Option[String]
) extends MethodLike

object RubyMethod:
  implicit val rubyMethodRwJson: ReadWriter[RubyMethod] = readwriter[ujson.Value].bimap[RubyMethod](
    x => ujson.Obj("name" -> x.name),
    json =>
        RubyMethod(
          name = json("name").str,
          parameterTypes = List.empty,
          returnType = XDefines.Any,
          baseTypeFullName = Option(json("name").str.split("\\.").dropRight(1).mkString("."))
        )
  )

case class RubyField(name: String, typeName: String) extends FieldLike derives ReadWriter

class RubyStubbedType(name: String, methods: List[RubyMethod], fields: List[RubyField])
    extends RubyType(name, methods, fields)
    with StubbedType[RubyMethod, RubyField]

object RubyStubbedType:
  implicit val rubyTypeRw: ReadWriter[RubyStubbedType] =
      readwriter[ujson.Value].bimap[RubyStubbedType](
        x =>
            ujson.Obj(
              "name" -> x.name,
              "methods" -> x.methods.map { method =>
                  ujson.Obj("name" -> method.name)
              },
              "fields" -> x.fields.map { field => write[RubyField](field) }
            ),
        json =>
            RubyStubbedType(
              name = json("name").str,
              methods = json.obj.get("methods") match
                case Some(jsonMethods) =>
                    val methodsList = read[List[RubyMethod]](jsonMethods)

                    methodsList.map { func =>
                      val baseTypeFullName = json("name").str

                      func.copy(name = func.name, baseTypeFullName = Option(baseTypeFullName))
                    }
                case None => Nil
              ,
              fields = json.obj.get("fields").map(read[List[RubyField]](_)).getOrElse(Nil)
            )
      )
end RubyStubbedType

case class RubyType(name: String, methods: List[RubyMethod], fields: List[RubyField])
    extends TypeLike[RubyMethod, RubyField]:

  @targetName("add")
  override def +(o: TypeLike[RubyMethod, RubyField]): TypeLike[RubyMethod, RubyField] =
      this.copy(methods = mergeMethods(o), fields = mergeFields(o))

  def hasConstructor: Boolean =
      methods.exists(_.name == Defines.Initialize)

object RubyType:
  implicit val rubyTypeRw: ReadWriter[RubyType] = readwriter[ujson.Value].bimap[RubyType](
    x =>
        ujson.Obj(
          "name" -> x.name,
          "methods" -> x.methods.map { method =>
              ujson.Obj("name" -> method.name)
          },
          "fields" -> x.fields.map { field => write[RubyField](field) }
        ),
    json =>
        RubyType(
          name = json("name").str,
          methods = json.obj.get("methods") match
            case Some(jsonMethods) =>
                val methodsList = read[List[RubyMethod]](jsonMethods)

                methodsList.map { func =>
                  val splitName        = func.name.split("\\.")
                  val baseTypeFullName = splitName.dropRight(1).mkString(".")

                  func.copy(name = func.name, baseTypeFullName = Option(baseTypeFullName))
                }
            case None => Nil
          ,
          fields = json.obj.get("fields").map(read[List[RubyField]](_)).getOrElse(Nil)
        )
  )
end RubyType
