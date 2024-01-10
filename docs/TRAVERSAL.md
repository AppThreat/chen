## Traversing an atom

Traversal queries begin with `atom`, followed by a primary node type from the below list.

| Name                | Comment                                                                             |
| ------------------- | ----------------------------------------------------------------------------------- |
| annotation          | Entire annotation                                                                   |
| annotationLiteral   | Literatal values in an annotation                                                   |
| annotationParameter | Parameter values                                                                    |
| call                | Call nodes                                                                          |
| configFile          | Configuration files                                                                 |
| file                | File                                                                                |
| identifier          | Identifier nodes                                                                    |
| imports             | Import nodes                                                                        |
| literal             | Literal nodes                                                                       |
| local               | Local variables                                                                     |
| method              | Method nodes                                                                        |
| ret                 | Return statements                                                                   |
| tag                 | Tag nodes                                                                           |
| typeDecl            | Type declarations                                                                   |
| typeRef             | Type references                                                                     |
| cfgNode             | Wrapper for multiple nodes such as annotation, call, control_structure, method, etc |
| declaration         | Wrapper for multiple noeds such as local, member, method, etc                       |

Example:

```scala
// List all annotations in the atom
atom.annotation.l

// List all files in the atom
atom.file.l

// Show the annotation list as json
atom.annotation.toJson
```

## annotation steps

- argumentIndex(int)
- argumentName(pattern)
- code(pattern)
- name(pattern)
- fullName(pattern)

## annotationLiteral steps

- argumentIndex(int)
- argumentName(pattern)
- code(pattern)
- name(pattern)

## annotationParameter steps

- code(pattern)

## call steps

- argumentIndex(int)
- argumentName(pattern)
- code(pattern)
- name(pattern)
- methodFullName(pattern)
- signature(pattern)
- typeFullName(pattern)

### call traversal

- argument - All argument nodes
- callee - All callee methods

## configFile steps

- name(string)
- content(string)

## file steps

- name(string)

## identifier steps

- argumentIndex(int)
- argumentName(pattern)
- code(pattern)
- name(pattern)
- typeFullName(pattern)

## import steps

- code(pattern)
- importedAs(string)
- importedEntity(string)
- isExplicit(boolean)
- isWildcard(boolean)

## literal steps

- argumentIndex(int)
- argumentName(pattern)
- code(pattern)
- typeFullName(pattern)

## local steps

- code(pattern)
- name(pattern)
- typeFullName(pattern)

## method steps

- code(pattern)
- filename(pattern)
- name(pattern)
- fullName(pattern)
- isExternal(boolean)
- signature(pattern)

### method traversal

- parameter - All MethodParameterIn nodes of the given method.
- literal - All literal nodes in the method.
- caller - All callers of this method

## ret steps

- argumentIndex(int)
- argumentName(pattern)
- code(pattern)

## tag steps

- name(pattern)

## typeDecl steps

- code(pattern)
- filename(pattern)
- name(pattern)
- fullName(pattern)
- isExternal(boolean)

## typeRef steps

- argumentIndex(int)
- argumentName(pattern)
- code(pattern)
- typeFullName(pattern)

## cfgNode steps

- code(pattern)

## declaration steps

- name(pattern)

## Helper step methods

Step methods accepting an integer would have variations such as Gt, Gte, Lt, Lte and Not to support integer operations.

Example:

```scala
atom.annotation.argumentIndexGt(1).l
```

Step methods accepting a string would have variations such as Exact and Not.

Example:

```scala
atom.annotation.argumentNameNot("foo").l
```

## Chaining step methods

If a step method return an iterator of type node then the method calls could be chained.

Example:

Parameters of all methods with the name `foo`.

```scala
atom.method.name("foo").parameter.l
```
