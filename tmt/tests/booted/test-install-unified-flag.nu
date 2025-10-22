use tap.nu

def main [] {
  tap begin "install help shows experimental unified flag"
  let help = (bootc install --help)
  # Grep-like check in nushell
  let has = ($help | lines | any { |l| $l | str contains "--experimental-unified-storage" })
  if (not $has) {
    error make { msg: "missing --experimental-unified-storage in help" }
  }
  tap ok
}


