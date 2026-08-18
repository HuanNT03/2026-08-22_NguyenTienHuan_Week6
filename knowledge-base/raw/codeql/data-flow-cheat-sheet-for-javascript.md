# Data flow cheat sheet for JavaScript

This article describes parts of the JavaScript libraries commonly used for variant analysis and in data flow queries.

## Taint tracking path queries

Use the following template to create a taint tracking path query:

```ql
/**
 * @kind path-problem
 */
import javascript

module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { ... }
  predicate isSink(DataFlow::Node node) { ... }
  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) { ... }
}

module MyFlow = TaintTracking::Global<MyConfig>;

from MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "taint from $@.", source.getNode(), "here"
```
This query reports flow paths which:

- Begin at a node matched by [isSource ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Configuration.qll/predicate.Configuration$Configuration$isSource.1.html).
- Step through variables, function calls, properties, strings, arrays, promises, exceptions, and steps added by [isAdditionalTaintStep ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/TaintTracking.qll/predicate.TaintTracking$TaintTracking$Configuration$isAdditionalTaintStep.2.html).
- End at a node matched by [isSink ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Configuration.qll/predicate.Configuration$Configuration$isSink.1.html).

See also: "[Global data flow ](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-javascript-and-typescript/#global-data-flow)" and "[Creating path queries ](#creating-path-queries)."

## DataFlow module

Use data flow nodes to match program elements independently of syntax. See also: "[Analyzing data flow in JavaScript and TypeScript ](analyzing-data-flow-in-javascript-and-typescript)."

Predicates in the `DataFlow::` module:

- [moduleImport ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$moduleImport.1.html) -- finds uses of a module
- [moduleMember ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$moduleMember.2.html) -- finds uses of a module member
- [globalVarRef ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$globalVarRef.1.html) -- finds uses of a global variable

Classes and member predicates in the `DataFlow::` module:

- [Node ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/DataFlow.qll/type.DataFlow$DataFlow$Node.html) -- something that can have a value, such as an expression, declaration, or SSA variable
    - [getALocalSource ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/DataFlow.qll/predicate.DataFlow$DataFlow$Node$getALocalSource.0.html) -- find the node that this came from
    - [getTopLevel ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/DataFlow.qll/predicate.DataFlow$DataFlow$Node$getTopLevel.0.html) -- top-level scope enclosing this node
    - [getFile ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/DataFlow.qll/predicate.DataFlow$DataFlow$Node$getFile.0.html) -- file containing this node
    - [getIntValue ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/DataFlow.qll/predicate.DataFlow$DataFlow$Node$getIntValue.0.html) -- value of this node if it's is an integer constant
    - [getStringValue ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/DataFlow.qll/predicate.DataFlow$DataFlow$Node$getStringValue.0.html) -- value of this node if it's is a string constant
    - [mayHaveBooleanValue ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/DataFlow.qll/predicate.DataFlow$DataFlow$Node$mayHaveBooleanValue.1.html) -- check if the value is `true` or `false`
- [SourceNode ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Sources.qll/type.Sources$SourceNode.html) extends [Node ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/DataFlow.qll/type.DataFlow$DataFlow$Node.html) -- function call, parameter, object creation, or reference to a property or global variable
    - [getALocalUse ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Sources.qll/predicate.Sources$SourceNode$getALocalUse.0.html) -- find nodes whose value came from this node
    - [getACall ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Sources.qll/predicate.Sources$SourceNode$getACall.0.html) -- find calls with this as the callee
    - [getAnInstantiation ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Sources.qll/predicate.Sources$SourceNode$getAnInstantiation.0.html) -- find `new`-calls with this as the callee
    - [getAnInvocation ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Sources.qll/predicate.Sources$SourceNode$getAnInvocation.0.html) -- find calls or `new`-calls with this as the callee
    - [getAMethodCall ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Sources.qll/predicate.Sources$SourceNode$getAMethodCall.1.html) -- find method calls with this as the receiver
    - [getAMemberCall ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Sources.qll/predicate.Sources$SourceNode$getAMemberCall.1.html) -- find calls with a member of this as the callee
    - [getAPropertyRead ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Sources.qll/predicate.Sources$SourceNode$getAPropertyRead.1.html) -- find property reads with this as the base
    - [getAPropertyWrite ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Sources.qll/predicate.Sources$SourceNode$getAPropertyWrite.1.html) -- find property writes with this as the base
    - [getAPropertySource ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Sources.qll/predicate.Sources$SourceNode$getAPropertySource.1.html) -- find nodes flowing into a property of this node
- [InvokeNode ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/type.Nodes$InvokeNode.html), [NewNode ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/type.Nodes$NewNode.html), [CallNode ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/type.Nodes$CallNode.html), [MethodCallNode ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/type.Nodes$MethodCallNode.html) extends [SourceNode ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Sources.qll/type.Sources$SourceNode.html) -- call to a function or constructor
    - [getArgument ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$InvokeNode$getArgument.1.html) -- an argument to the call
    - [getCalleeNode ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$InvokeNode$getCalleeNode.0.html) -- node being invoked as a function
    - [getCalleeName ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$InvokeNode$getCalleeName.0.html) -- name of the variable or property being called
    - [getOptionArgument ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$InvokeNode$getOptionArgument.2.html) -- a "named argument" passed in through an object literal
    - [getCallback ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$InvokeNode$getCallback.1.html) -- a function passed as a callback
    - [getACallee ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$InvokeNode$getACallee.0.html) - a function being called here
    - (MethodCallNode).\ [getMethodName ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$MethodCallNode$getMethodName.0.html) -- name of the method being invoked
    - (MethodCallNode).\ [getReceiver ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$CallNode$getReceiver.0.html) -- receiver of the method call
- [FunctionNode ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/type.Nodes$FunctionNode.html) extends [SourceNode ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Sources.qll/type.Sources$SourceNode.html) -- definition of a function, including closures, methods, and class constructors
    - [getName ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$FunctionNode$getName.0.html) -- name of the function, derived from a variable or property name
    - [getParameter ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$FunctionNode$getParameter.1.html) -- a parameter of the function
    - [getReceiver ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$FunctionNode$getReceiver.0.html) -- the node representing the value of `this`
    - [getAReturn ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$FunctionNode$getAReturn.0.html) -- get a returned expression
- [ParameterNode ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/type.Nodes$ParameterNode.html) extends [SourceNode ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Sources.qll/type.Sources$SourceNode.html) -- parameter of a function
    - [getName ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$ParameterNode$getName.0.html) -- the parameter name, if it has one
- [ClassNode ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/type.Nodes$ClassNode.html) extends [SourceNode ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Sources.qll/type.Sources$SourceNode.html) -- class declaration or function that acts as a class
    - [getName ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$ClassNode$getName.0.html) -- name of the class, derived from a variable or property name
    - [getConstructor ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$ClassNode$getConstructor.0.html) -- the constructor function
    - [getInstanceMethod ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$ClassNode$getInstanceMethod.1.html) -- get an instance method by name
    - [getStaticMethod ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$ClassNode$getStaticMethod.1.html) -- get a static method by name
    - [getAnInstanceReference ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$ClassNode$getAnInstanceReference.0.html) -- find references to an instance of the class
    - [getAClassReference ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$ClassNode$getAClassReference.0.html) -- find references to the class itself
- [ObjectLiteralNode ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/type.Nodes$ObjectLiteralNode.html) extends [SourceNode ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Sources.qll/type.Sources$SourceNode.html) -- object literal
    - [getAPropertyWrite ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Sources.qll/predicate.Sources$SourceNode$getAPropertyWrite.1.html) -- a property in the object literal
    - [getAPropertySource ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Sources.qll/predicate.Sources$SourceNode$getAPropertySource.1.html) -- value flowing into a property
- [ArrayCreationNode ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/type.Nodes$ArrayCreationNode.html) extends [SourceNode ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Sources.qll/type.Sources$SourceNode.html) -- array literal or call to `Array` constructor
    - [getElement ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$ArrayCreationNode$getElement.1.html) -- an element of the array
- [PropRef ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/DataFlow.qll/type.DataFlow$DataFlow$PropRef.html), [PropRead ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/DataFlow.qll/type.DataFlow$DataFlow$PropRead.html), [PropWrite ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/DataFlow.qll/type.DataFlow$DataFlow$PropWrite.html) -- read or write of a property
    - [getPropertyName ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/DataFlow.qll/predicate.DataFlow$DataFlow$PropRef$getPropertyName.0.html) -- name of the property, if it is constant
    - [getPropertyNameExpr ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/DataFlow.qll/predicate.DataFlow$DataFlow$PropRef$getPropertyNameExpr.0.html) -- expression holding the name of the property
    - [getBase ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/DataFlow.qll/predicate.DataFlow$DataFlow$PropRef$getBase.0.html) -- object whose property is accessed
    - (PropWrite).\ [getRhs ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/DataFlow.qll/predicate.DataFlow$DataFlow$PropWrite$getRhs.0.html) -- right-hand side of the property assignment

## StringOps module

- StringOps::[Concatenation ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/StringOps.qll/type.StringOps$StringOps$Concatenation.html) -- string concatenation, using a plus operator, template literal, or array join call
- StringOps::[StartsWith ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/StringOps.qll/type.StringOps$StringOps$StartsWith.html) -- check if a string starts with something
- StringOps::[EndsWith ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/StringOps.qll/type.StringOps$StringOps$EndsWith.html) -- check if a string ends with something
- StringOps::[Includes ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/StringOps.qll/type.StringOps$StringOps$Includes.html) -- check if a string contains something
- StringOps::[RegExpTest ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/StringOps.qll/type.StringOps$StringOps$RegExpTest.html) -- check if a string matches a RegExp

## Utility

- [ExtendCall ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/Extend.qll/type.Extend$ExtendCall.html) -- call that copies properties from one object to another
- [JsonParserCall ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/JsonParsers.qll/type.JsonParsers$JsonParserCall.html) -- call that deserializes a JSON string
- [JsonStringifyCall ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/JsonStringifiers.qll/type.JsonStringifiers$JsonStringifyCall.html) -- call that serializes a JSON string
- [PropertyProjection ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/frameworks/PropertyProjection.qll/type.PropertyProjection$PropertyProjection.html) -- call that extracts nested properties by name

## System and Network

- [ClientRequest ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/frameworks/ClientRequests.qll/type.ClientRequests$ClientRequest.html) -- outgoing network request
- [DatabaseAccess ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/Concepts.qll/type.Concepts$DatabaseAccess.html) -- query being submitted to a database
- [FileNameSource ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/Concepts.qll/type.Concepts$FileNameSource.html) -- reference to a filename
- [FileSystemAccess ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/Concepts.qll/type.Concepts$FileSystemAccess.html) -- file system operation
    - [FileSystemReadAccess ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/Concepts.qll/type.Concepts$FileSystemReadAccess.html) -- reading the contents of a file
    - [FileSystemWriteAccess ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/Concepts.qll/type.Concepts$FileSystemWriteAccess.html) -- writing to the contents of a file
- [PersistentReadAccess ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/Concepts.qll/type.Concepts$PersistentReadAccess.html) -- reading from persistent storage, like cookies
- [PersistentWriteAccess ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/Concepts.qll/type.Concepts$PersistentWriteAccess.html) -- writing to persistent storage
- [SystemCommandExecution ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/Concepts.qll/type.Concepts$SystemCommandExecution.html) -- execution of a system command

## Untrusted data

- [RemoteFlowSource ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/security/dataflow/RemoteFlowSources.qll/type.RemoteFlowSources$Cached$RemoteFlowSource.html) -- source of untrusted user input
    - [isUserControlledObject ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/security/dataflow/RemoteFlowSources.qll/predicate.RemoteFlowSources$Cached$RemoteFlowSource$isUserControlledObject.0.html) -- is the input deserialized to a JSON-like object? (as opposed to just being a string)
- [ClientSideRemoteFlowSource ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/security/dataflow/RemoteFlowSources.qll/type.RemoteFlowSources$Cached$ClientSideRemoteFlowSource.html) extends [RemoteFlowSource ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/security/dataflow/RemoteFlowSources.qll/type.RemoteFlowSources$Cached$RemoteFlowSource.html) -- input specific to the browser environment
    - [getKind ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/security/dataflow/RemoteFlowSources.qll/predicate.RemoteFlowSources$Cached$ClientSideRemoteFlowSource$getKind.0.html) -- is this derived from the `path`, `fragment`, `query`, `url`, or `name`?
- HTTP::[RequestInputAccess ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/frameworks/HTTP.qll/type.HTTP$HTTP$RequestInputAccess.html) extends [RemoteFlowSource ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/security/dataflow/RemoteFlowSources.qll/type.RemoteFlowSources$Cached$RemoteFlowSource.html) -- input from an incoming HTTP request
    - [getKind ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/frameworks/HTTP.qll/predicate.HTTP$HTTP$RequestInputAccess$getKind.0.html) -- is this derived from a `parameter`, `header`, `body`, `url`, or `cookie`?
- HTTP::[RequestHeaderAccess ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/frameworks/HTTP.qll/type.HTTP$HTTP$RequestHeaderAccess.html) extends [RequestInputAccess ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/frameworks/HTTP.qll/type.HTTP$HTTP$RequestInputAccess.html) -- access to a specific header
    - [getAHeaderName ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/frameworks/HTTP.qll/predicate.HTTP$HTTP$RequestHeaderAccess$getAHeaderName.0.html) -- the name of a header being accessed

Note: some [RemoteFlowSource ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/security/dataflow/RemoteFlowSources.qll/type.RemoteFlowSources$Cached$RemoteFlowSource.html) instances, such as input from a web socket,
belong to none of the specific subcategories above.

## Files

-  [File ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/Files.qll/type.Files$File.html),
   [Folder ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/Files.qll/type.Files$Folder.html) extends
   [Container ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/Files.qll/type.Files$Container.html) -- file or folder in the database

   -  [getBaseName ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/Files.qll/predicate.Files$Container$getBaseName.0.html) -- the name of the file or folder
   -  [getRelativePath ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/Files.qll/predicate.Files$Container$getRelativePath.0.html) -- path relative to the database root

## AST nodes

See also: "[Abstract syntax tree classes for working with JavaScript and TypeScript programs ](abstract-syntax-tree-classes-for-working-with-javascript-and-typescript-programs)."

Conversion between DataFlow and AST nodes:

- [Node.asExpr() ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/DataFlow.qll/predicate.DataFlow$DataFlow$Node$asExpr.0.html) -- convert node to an expression, if possible
- [Expr.flow() ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/AST.qll/predicate.AST$AST$ValueNode$flow.0.html) -- convert expression to a node (always possible)
- [DataFlow::valueNode ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/DataFlow.qll/predicate.DataFlow$DataFlow$valueNode.1.html) -- convert expression or declaration to a node
- [DataFlow::parameterNode ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/DataFlow.qll/predicate.DataFlow$DataFlow$parameterNode.1.html) -- convert a parameter to a node
- [DataFlow::thisNode ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/DataFlow.qll/predicate.DataFlow$DataFlow$thisNode.1.html) -- get the receiver node of a function

## String matching

-  x.\ [matches ](https://codeql.github.com/codeql-standard-libraries/javascript/predicate.string$matches.1.html)\ ("escape%") -- holds if x starts with "escape"
-  x.\ [regexpMatch ](https://codeql.github.com/codeql-standard-libraries/javascript/predicate.string$regexpMatch.1.html)\ ("escape.*") -- holds if x starts with "escape"
-  x.\ [regexpMatch ](https://codeql.github.com/codeql-standard-libraries/javascript/predicate.string$regexpMatch.1.html)\ ("(?i).*escape.*") -- holds if x contains
   "escape" (case insensitive)

## Access paths

When multiple property accesses are chained together they form what's called an "access path".

To identify nodes based on access paths, use the following predicates in [AccessPath ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/GlobalAccessPaths.qll/module.GlobalAccessPaths$AccessPath.html) module:

- AccessPath::[getAReferenceTo ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/GlobalAccessPaths.qll/predicate.GlobalAccessPaths$AccessPath$getAReferenceTo.2.html) -- find nodes that refer to the given access path
- AccessPath::[getAnAssignmentTo ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/GlobalAccessPaths.qll/predicate.GlobalAccessPaths$AccessPath$getAnAssignmentTo.2.html) -- finds nodes that are assigned to the given access path
- AccessPath::[getAnAliasedSourceNode ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/GlobalAccessPaths.qll/predicate.GlobalAccessPaths$AccessPath$getAnAliasedSourceNode.1.html) -- finds nodes that refer to the same access path

`getAReferenceTo` and `getAnAssignmentTo` have a 1-argument version for global access paths, and a 2-argument version for access paths starting at a given node.

## Type tracking

See also: "[Using type tracking for API modeling ](using-type-tracking-for-api-modeling)."

Use the following template to define forward type tracking predicates:

```ql
import DataFlow

SourceNode myType(TypeTracker t) {
  t.start() and
  result = /* SourceNode to track */
  or
  exists(TypeTracker t2 |
    result = myType(t2).track(t2, t)
  )
}

SourceNode myType() {
  result = myType(TypeTracker::end())
}
```
Use the following template to define backward type tracking predicates:

```ql
import DataFlow

SourceNode myType(TypeBackTracker t) {
  t.start() and
  result = (/* argument to track */).getALocalSource()
  or
  exists(TypeBackTracker t2 |
    result = myType(t2).backtrack(t2, t)
  )
}

SourceNode myType() {
  result = myType(TypeBackTracker::end())
}
```
## Troubleshooting

-  Using a call node as as sink? Try using [getArgument ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$InvokeNode$getArgument.1.html)
   to get an *argument* of the call node instead.
-  Trying to use [moduleImport ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$moduleImport.1.html)
   or [moduleMember ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Nodes.qll/predicate.Nodes$moduleMember.2.html)
   as a call node?
   Try using [getACall ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/Sources.qll/predicate.Sources$SourceNode$getACall.0.html)
   to get a *call* to the imported function, instead of the function itself.
-  Compilation fails due to incompatible types? Make sure AST nodes and
   DataFlow nodes are not mixed up. Use [asExpr() ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/dataflow/DataFlow.qll/predicate.DataFlow$DataFlow$Node$asExpr.0.html) or
   [flow() ](https://codeql.github.com/codeql-standard-libraries/javascript/semmle/javascript/AST.qll/predicate.AST$AST$ValueNode$flow.0.html) to convert.

## Further reading

- [Exploring data flow with path queries  ](https://docs.github.com/en/code-security/codeql-for-vs-code/getting-started-with-codeql-for-vs-code/exploring-data-flow-with-path-queries) in the GitHub documentation.
