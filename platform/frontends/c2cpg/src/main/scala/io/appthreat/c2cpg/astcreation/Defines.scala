package io.appthreat.c2cpg.astcreation

object Defines:
  val anyTypeName: String            = "ANY"
  val voidTypeName: String           = "void"
  val qualifiedNameSeparator: String = "::"
  val empty                          = "<empty>"
  val operatorPointerCall            = "<operator>.pointerCall"
  val operatorConstructorInitializer = "<operator>.constructorInitializer"
  val operatorTypeOf                 = "<operator>.typeOf"
  val operatorTypeId                 = "<operator>.typeId"
  val operatorAlignOf                = "<operator>.alignOf"
  // `sizeof...(pack)` counts elements and is not a byte size, so it deliberately does not share
  // the `<operator>.sizeOf` prefix that passes match on
  val operatorParameterPackSize = "<operator>.parameterPackSize"
  val operatorNoexcept          = "<operator>.noexcept"
  val operatorLabelAddress      = "<operator>.labelAddress"
  // `obj.*pm` and `ptr->*pm`: a member selected through a pointer to member, not a named field
  val operatorPointerToMember         = "<operator>.pointerToMember"
  val operatorIndirectPointerToMember = "<operator>.indirectPointerToMember"
  val operatorMax                     = "<operator>.max"
  val operatorMin                     = "<operator>.min"
  val operatorEllipses                = "<operator>.op_ellipses"
  val operatorUnknown                 = "<operator>.unknown"
  val operatorCall                    = "<operator>()"
  val operatorExpressionList          = "<operator>.expressionList"
  val operatorNew                     = "<operator>.new"
  val operatorThrow                   = "<operator>.throw"
  val operatorBracketedPrimary        = "<operator>.bracketedPrimary"

  /** On an `#include`'s IMPORT node: the file the include resolved to (absolute). */
  val IncludeResolvedPathTag = "include-resolved-path"

  /** On an `#include`'s IMPORT node: `true` when it names a system header (`<...>`). */
  val IncludeSystemTag = "include-system"

  /** On a call to a function declared only in another file (a header): that file (absolute). */
  val CalleeDeclaredInTag = "callee-declared-in"

  /** On an identifier that reads a global variable, an enumerator or a function as a value declared
    * in another file (a header): that file (absolute).
    */
  val RefDeclaredInTag = "ref-declared-in"

  /** On a member access whose struct or class is defined in another file (a header): that file
    * (absolute).
    */
  val TypeDeclaredInTag = "type-declared-in"

  /** On the call a macro invocation builds: `<macro name>@<defining file>` for each other macro the
    * invocation's expansion names (in its arguments or its definition), the defining file absolute.
    * An expansion of a nested macro is a use of that macro at the invocation's own site.
    */
  val NestedMacroTag = "nested-macro"

  /** A macro invocation the expression tree does not carry (a constant the EDG front end folded,
    * such as an object-like macro in a `case` label), tagged on its file's own method:
    * `<name>@<line>:<column>@<definition file>`.
    */
  val MacroUseTag = "macro-use"

  /** On a call that constructs an object of a class declared elsewhere (a declaration's constructor
    * initializer, a `new`): the constructed type's simple name. With `callee-declared-in` it names
    * the class's header.
    */
  val ConstructsTypeTag = "constructs-type"
end Defines
