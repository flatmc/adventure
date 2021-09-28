import shell from "shelljs"
import path from "path"
import fs from "fs"

{
  const argv0 = process.argv[0].split("/")
  if (argv0[argv0.length - 1] !== "ts-node") {
    console.log("Script needs to be run with ts-node.")
    process.exit(1)
  }
}

const OUT_DIR = "dist"
const WORKDIR = path.join(OUT_DIR, "flatearth_adventure")

shell.exec("tsc")
shell.exec(
  `pkg ${path.join(
    "build",
    "main.js"
  )} --out-path ${OUT_DIR} --config package.json`
)

if (!fs.existsSync(WORKDIR)) shell.mkdir(WORKDIR)

// copy launcher resources
shell.cp("-R", path.join("resources", "launcher", "*"), path.join(WORKDIR))
