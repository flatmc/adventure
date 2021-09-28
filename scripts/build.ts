import shell from "shelljs"

{
  const argv0 = process.argv[0].split("/")
  if (argv0[argv0.length - 1] !== "ts-node") {
    console.log("Script needs to be run with ts-node.")
    process.exit(1)
  }
}

shell.exec("tsc")
shell.exec("pkg build/main.js --out-path dist --config package.json")
