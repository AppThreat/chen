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
  val StorageClassTag = "storage-class"

  /** The compile-time value of an integer constant expression a frontend evaluated, in decimal:
    * `sizeof(T)`, an enumerator, a `const` integral (also one a header defines), `N * 4`.
    */
  val ConstValueTag      = "const-value"
  val StorageClassStatic = "static"

  /** A GCC/Clang function attribute written on a declaration or definition, normalised
    * (`__malloc__` -> `malloc`, `alloc_size(1, 2)` -> `alloc_size(1,2)`): the declared semantics a
    * header gives a function whose body is out of scope. On the METHOD, one tag per attribute.
    */
  val FunctionAttributeTag = "fn-attr"

  /** On an addition, subtraction, compound assignment or increment over a pointer or an array:
    * `add:<i>` or `sub:<i>` with the argument index of the pointer operand (`p + n` is `add:1`, `n
    * + p` is `add:2`, `p -= n` is `sub:1`), and `diff` for the distance between two pointers.
    */
  val PointerArithmeticTag = "ptr-arith"

  /** On a LOCAL or METHOD_PARAMETER_IN (C/C++): how the variable is referenced, one tag per kind -
    * `address-taken` (its address leaves, so it can change unnamed), `modified` (written after its
    * declaration), or `read-only`.
    */
  val ReferenceKindTag = "ref"

  /** C/C++ macro invocations. Each invocation of a file has an index: its INLINED call and the
    * nodes its expansion produced carry `macro-invocation=<index>`; an invocation nested in another
    * (an argument that is itself a macro) carries `macro-parent=<index>` of the enclosing one. A
    * node written in a macro's definition carries `macro-origin=<file>:<line>:<column>` there. The
    * INLINED call's arguments are copies of subtrees of the expansion (the AST is a tree), each
    * node of them marked `macro-argument-copy`.
    */
  val MacroInvocationTag   = "macro-invocation"
  val MacroParentTag       = "macro-parent"
  val MacroOriginTag       = "macro-origin"
  val MacroArgumentCopyTag = "macro-argument-copy"

  /** On a CALL to a user-defined operator (`a + b` calling `Vec2::operator+`): the built-in
    * operator the expression is written with (`<operator>.addition`), so a consumer that matches
    * operator names still finds the expression after the frontend linked it to its method.
    */
  val OperatorCallTag = "operator-call"

  /** On a CALL that a frontend linked to the generic definition of a function template: the
    * signature of the instance the call uses (`short(short,short)` for `clampAdd<short>`).
    */
  val TemplateInstanceTag = "template-instance"

  /** On a C++ `<operator>.new` or `<operator>.delete` CALL: which form it is. `new` is `scalar`,
    * `array` (`new T[n]`) or `placement` (`new (buf) T`); `delete` is `scalar` or `array`
    * (`delete[]`).
    */
  val AllocFormTag       = "alloc-form"
  val AllocFormScalar    = "scalar"
  val AllocFormArray     = "array"
  val AllocFormPlacement = "placement"

  val UnresolvedNamespace = "<unresolvedNamespace>"
  val UnresolvedSignature = "<unresolvedSignature>"

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
