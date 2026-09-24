package io.appthreat.x2cpg

object Defines:
  // The following two defines should be used for type and method full names to
  // indicate unresolved static type information. Using them enables
  // the closed source backend to apply policies in a less strict fashion.
  // The most notable case is the METHOD_FULL_NAME property of a CALL node.
  // As example consider a call to a method `foo(someArg)` which cannot be
  // resolved. The METHOD_FULL_NAME should be given as
  // "<unresolvedNamespace>.foo:<unresolvedSignature>(1)". If the namespace is known
  // the METHOD_FULL_NAME should be given as
  // "some.namespace.foo:<unresolvedSignature>(1)". Thereby the number in parenthesis
  // is the number of call arguments.
  // Note that this schema and thus the defines only makes sense for statically
  // typed languages with a package/namespace structure like Java, CSharp, etc..
  val Any = "ANY"

  // A frontend-recorded storage class on a LOCAL that has static storage duration (C/C++
  // `static` inside a function): the schema has no property or MODIFIER child for it on a LOCAL.
  val StorageClassTag    = "storage-class"
  val StorageClassStatic = "static"

  /** A GCC/Clang function attribute written on a declaration or definition, normalised
    * (`__malloc__` -> `malloc`, `alloc_size(1, 2)` -> `alloc_size(1,2)`): the declared semantics a
    * header gives a function whose body is out of scope. On the METHOD, one tag per attribute.
    */
  val FunctionAttributeTag = "fn-attr"
  val UnresolvedNamespace  = "<unresolvedNamespace>"
  val UnresolvedSignature  = "<unresolvedSignature>"

  // Name of the synthetic, static method that contains the initialization of member variables.
  val StaticInitMethodName = "<clinit>"

  // Name of the constructor.
  val ConstructorMethodName = "<init>"

  // In some languages like Javascript dynamic calls do not provide any statically known
  // method/function interface information. In those cases please use this value.
  val DynamicCallUnknownFullName = "<unknownFullName>"

  val LeftAngularBracket = "<"
  val Unknown            = "<unknown>"
  // Anonymous functions, lambdas, and closures, follow the naming scheme of $LambdaPrefix$int
  val ClosurePrefix = "<lambda>"
end Defines
