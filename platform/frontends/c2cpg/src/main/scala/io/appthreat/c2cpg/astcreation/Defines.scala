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
end Defines
