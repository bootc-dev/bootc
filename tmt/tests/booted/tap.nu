# A simple nushell "library" for the
# "Test anything protocol":
# https://testanything.org/tap-version-14-specification.html
export def begin [description] {
  print "TAP version 14"
  print $description
}

export def ok [] {
  print "ok"
}

export def fail [] {
  print "not ok"
}
