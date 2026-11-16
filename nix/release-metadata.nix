# Release metadata of the workspace members this repository publishes to the
# pkgre registry.
#
# `check { workspace, members }` takes the parsed root manifest and a list of
# `{ path, manifest }` members, and returns one message per rule that a member
# whose `package.publish` is exactly `[ "pkgre" ]` breaks. Such a member is
# released with the workspace version, and carries the metadata crates.io
# requires or shows: a description, a license, a repository, and keywords it
# accepts. A field a member inherits from the workspace counts as set when the
# workspace sets it.
{ lib }:

let
  # crates.io accepts at most 5 keywords of at most 20 characters, each of
  # ASCII letters, digits, `_`, `-` and `+`, starting with a letter or digit
  keywordLimit = 5;
  keywordLengthLimit = 20;
  validKeyword = keyword: builtins.match "[A-Za-z0-9][A-Za-z0-9_+-]*" keyword != null;

  requiredFields = [
    "description"
    "license"
    "repository"
  ];

  inheritsWorkspace = value: builtins.isAttrs value && value == { workspace = true; };

  # the value a package carries for `name`, following `name.workspace = true`
  # into the workspace package table
  valueOf =
    workspacePackage: package: name:
    let
      value = package.${name} or null;
    in
    if value == null then
      null
    else if inheritsWorkspace value then
      workspacePackage.${name} or null
    else
      value;

  errorsFor =
    workspace: path: manifest:
    let
      where = path;
      package = manifest.package;
      workspacePackage = workspace.workspace.package or { };

      versionErrors =
        if !(inheritsWorkspace (package.version or null)) then
          [ "${where}: set version.workspace = true, so that the member takes the workspace version" ]
        else if workspacePackage.version or null == null then
          [ "${where}: the workspace sets no package.version" ]
        else
          [ ];

      fieldErrors = map (name: "${where}: missing ${name}") (
        builtins.filter (name: valueOf workspacePackage package name == null) requiredFields
      );

      keywords = package.keywords or [ ];
      keywordErrors =
        lib.optional (builtins.length keywords > keywordLimit)
          "${where}: ${toString (builtins.length keywords)} keywords, crates.io accepts at most ${toString keywordLimit}"
        ++ lib.concatMap (
          keyword:
          lib.optional (builtins.stringLength keyword > keywordLengthLimit)
            "${where}: keyword ${builtins.toJSON keyword} is longer than ${toString keywordLengthLimit} characters"
          ++
            lib.optional (!(validKeyword keyword))
              "${where}: keyword ${builtins.toJSON keyword} must be ASCII letters, digits, '_', '-' or '+' and start with a letter or digit"
        ) keywords;
    in
    versionErrors ++ fieldErrors ++ keywordErrors;
in
{
  check =
    { workspace, members }:
    lib.concatMap (
      member:
      if (member.manifest.package.publish or null) == [ "pkgre" ] then
        errorsFor workspace member.path member.manifest
      else
        [ ]
    ) members;
}
