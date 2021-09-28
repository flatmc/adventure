import {
  Client,
  Authenticator,
  ILauncherOptions,
} from "minecraft-launcher-core"
import fs from "fs"
import path from "path"
import cp from "child_process"

type Config = {
  username: string
  password: string | null
}

const sampleConfig: Config = {
  username: "noob",
  password: null,
}

/**
 * Simple, opinionated Logger for use with Node.js and Web Browsers with no
 * additional dependencies.
 *
 * The logger supports and auto-detects the following environments:
 * - Node.js (with and without JSDOM)
 * = Browser
 * - Electron
 * - React Native - Logs to console or browser window depending on whether a debugger is connected
 * - Unit Test & CI/CD - Logs are disabled by default
 *
 * The default log level is `INFO` for Node.js production environments and `DEBUG` for
 * anything else. A different default level can be specified using an environment
 * variable `LOG_LEVEL` (for Node.js like environments) or by setting `window.LOG_LEVEL`
 * (for Browser like environments).
 *
 * The logger will automatically detect if the used terminal supports colored output.
 * To disable colored terminal output set `FORCE_COLOR` environment variable to `0` or
 * `false`. To enforce colors regardless of any detected support, set `FORCE_COLOR` to
 * `1` or `true`.
 *
 * @example
 * import Logger from "./logger";
 *
 * const logger = Logger.create(__filename);
 *
 * function myFunc() {
 *   try {
 *     logger.info("Hello!");
 *     logger.info("With payload:", { foo: "bar" });
 *     // ...
 *   }
 *   catch (error) {
 *     logger.error("Oh no!", { error });
 *   }
 * }
 */
/* eslint-disable @typescript-eslint/no-empty-function, @typescript-eslint/no-explicit-any, no-dupe-class-members, no-console, no-param-reassign, no-var */

// Avoid TypeScript errors when trying to access globals not available in our target environment
declare var global: any
const process = global?.process
const window = global?.window
const document = global?.document
const navigator = global?.navigator

/**
 * Supported log levels. Use `NONE` to disable logging completely. By default
 * only `DEBUG` and above are logged. To set a different default level set
 * the `LOG_LEVEL` environment variable or explicitly set the
 * {@see Logger.defaultLevel} property. Set to `NONE` to fully disable logging.
 */
export enum LogLevels {
  /** Lowest debug level; This will not be logged unless explicitly enabled */
  SILLY = 0,
  /** Debug messages for development environments */
  DEBUG = 1,
  /** Info messages will be logged in production environments by default */
  INFO = 2,
  /** Warning about a potential issue or an expected error occured */
  WARN = 3,
  /** An unexpected error occurred */
  ERROR = 4,
  /** Critical application error that cannot be recovered */
  CRITICAL = 5,
  /** Disable logging */
  NONE = 99,
}

/** Names of the log levels used for display */
export const LogLevelNames: { [key in LogLevels]: string } = {
  [LogLevels.SILLY]: "SILLY",
  [LogLevels.DEBUG]: "DEBUG",
  [LogLevels.INFO]: "INFO",
  [LogLevels.WARN]: "WARN",
  [LogLevels.ERROR]: "ERROR",
  [LogLevels.CRITICAL]: "CRITICAL",
  [LogLevels.NONE]: "NONE",
}

/**
 * Static mapping of error levels to `console.*` functions.
 * While technically this can used to customize the log output to use a different
 * function such as `process.stdout.write`, it is not recommended. Instead create
 * a new log handler function and register it using {@see Logger.registerHandler}.
 */
export const ConsoleLogFuncs: {
  [key in LogLevels]: (...args: any[]) => void
} = {
  [LogLevels.SILLY]: console.debug.bind(console),
  [LogLevels.DEBUG]: console.debug.bind(console),
  [LogLevels.INFO]: console.info.bind(console),
  [LogLevels.WARN]: console.warn.bind(console),
  [LogLevels.ERROR]: console.error.bind(console),
  [LogLevels.CRITICAL]: console.error.bind(console),
  [LogLevels.NONE]: () => {}, // no-op
}

/** Any kind of payload data, a plain old JavaScript object */
export type Payload = { [key: string]: any; error?: Error }
/** A single log entry */
export interface LogEntry {
  timestamp: Date
  level: LogLevels
  message: string
  payload?: Payload
  meta?: Payload
}
/** A custom log handler */
export type LogHandlerFunc = (logEntry: LogEntry) => void

/**
 * Logger
 */
export default class Logger {
  /**
   * Fields that will automatically be scrubbed from logs. Field names will automatically transformed to lower case
   * and special characters stripped before matching the string, so e.g. "access_token", "access-token" and
   * "accessToken" will all match "accesstoken".
   *
   * To disable scrubbing, set this to an empty array
   */
  static scrubValues = [
    "password",
    "newpassword",
    "oldpassword",
    "secret",
    "passwd",
    "apikey",
    "accesstoken",
    "authtoken",
    "creds",
    "credentials",
    "mysqlpwd",
    "stripetoken",
    "cardnumber",
  ]

  /** A list of class names, primarily from network libraries, that will be collapsed in the logs in order to keep it shorter and more readable */
  static collapseClasses = [
    "ClientRequest",
    "IncomingMessage",
    "Buffer",
    "TLSSocket",
    "Socket",
    "WebSocket",
    "WebSocketTransport",
    "ReadableState",
    "WritableState",
    "HttpsAgent",
    "HttpAgent",
    "CDPSession", // Puppeteer
  ]

  /** Regular expression that can be used to check for possible credit card numbers when scrubbing fields */
  private static _creditCardRegEx =
    /^(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})$/

  /** Metadata shared between all instances of the Logger */
  private static _globalMetaData?: Payload

  /** List of log handler functions */
  private static _handlers: LogHandlerFunc[] = []

  /**
   * Instantiates a new logger
   *
   * @param tag - Logger tag, e.g. the name of the current JavaScript file.
   *   For convenience, paths such as `__filename` will automatically be truncated
   *   to the file name only.
   * @param meta - Logger meta, e.g. the if of the vessel currently logging
   *
   * @example
   * const logger = Logger.create(__filename);
   *
   */
  static create(tag?: string, meta?: Payload): Logger {
    return new Logger(tag, meta)
  }

  /** Registers a new log handler */
  static registerHandler(handlerFunc: LogHandlerFunc) {
    Logger._handlers.push(handlerFunc)
  }

  /** Removes a log handler */
  static unregisterHandler(handlerFunc: LogHandlerFunc) {
    Logger._handlers = Logger._handlers.filter((func) => func === handlerFunc)
  }

  /** Removes all log handlers */
  static clearHandlers() {
    Logger._handlers = []
  }

  /**
   * Returns `true` if code is running with JSDOM
   */
  static get isJSDOM(): boolean {
    return (
      navigator?.userAgent?.includes("Node.js") ||
      navigator?.userAgent?.includes("jsdom")
    )
  }

  /**
   * Returns `true` if code is running in a web browser environment
   */
  static get isWebWorker(): boolean {
    return (
      global &&
      typeof global.WorkerGlobalScope !== "undefined" &&
      global.self instanceof global.WorkerGlobalScope
    )
  }

  /**
   * Returns `true` if code is running in a web browser environment
   */
  static get isBrowser(): boolean {
    return (
      (typeof window !== "undefined" || Logger.isWebWorker) && !Logger.isJSDOM
    )
  }

  /**
   * Returns `true` if code is running in a web browser environment
   */
  static get isIE(): boolean {
    return (
      Logger.isBrowser &&
      document &&
      window &&
      document.documentMode &&
      window.StyleMedia
    )
  }

  /**
   * Returns `true` if code is running in React Native
   */
  static get isReactNative(): boolean {
    return Logger.isBrowser && navigator && navigator.product === "ReactNative"
  }

  /**
   * Returns `true` if code is running in React Native and the Debugger is attached
   */
  static get isReactNativeDebugger(): boolean {
    return (
      Logger.isReactNative &&
      typeof global?.DedicatedWorkerGlobalScope !== "undefined"
    )
  }

  /**
   * Returns `true` if code is running in a Node.js-like environment (including Electron)
   */
  static get isNode(): boolean {
    // Note that Webpack et al are often adding process, module, require, etc.
    return (
      typeof process === "object" &&
      typeof process.env === "object" &&
      !Logger.isBrowser
    )
  }

  /** Returns `true` if code is running in Electron */
  static get isElectron(): boolean {
    const userAgent = navigator?.userAgent?.toLowerCase()
    if (userAgent.includes(" electron/")) {
      // Test for Electron in case no Node.js environment is loaded
      return true
    }
    return Logger.isNode && typeof process?.versions?.electron !== "undefined"
  }

  /** Returns `true` if running in a CI environment, e.g. during an automated build */
  static get isCI(): boolean {
    if (!Logger.isNode) {
      return false
    }
    const { CI, CONTINUOUS_INTEGRATION, BUILD_NUMBER, RUN_ID } = process.env
    // Shamelessly stolen from https://github.com/watson/ci-info
    return !!(
      CI || // Travis CI, CircleCI, Cirrus CI, Gitlab CI, Appveyor, CodeShip, dsari
      CONTINUOUS_INTEGRATION || // Travis CI, Cirrus CI
      BUILD_NUMBER || // Jenkins, TeamCity
      RUN_ID || // TaskCluster, dsari
      false
    )
  }

  /** Retruns `true` if running as part of a unit test */
  static get isUnitTest(): boolean {
    if (!Logger.isNode) {
      return false
    }
    const { JEST_WORKER_ID } = process.env
    return !!(JEST_WORKER_ID || typeof global?.it === "function")
  }

  /**
   * Retruns `true` if `--silent` is passed on command line, e.g. when executed via an `npm` script
   */
  static get isSilent(): boolean {
    if (!Logger.isNode) {
      return false
    }
    return process.argv?.includes("--silent")
  }

  /** Checking if console exists */
  static get hasConsole(): boolean {
    // eslint-disable-next-line @typescript-eslint/unbound-method
    return !!(
      console.log &&
      console.debug &&
      console.info &&
      console.warn &&
      console.error
    )
  }

  /** Enable/disable all logging */
  static enabled: boolean =
    !Logger.isCI && !Logger.isSilent && !Logger.isUnitTest && Logger.hasConsole

  /** The default log level if no other option is specified */
  static defaultLevel: LogLevels =
    Logger._parseLogLevel(process?.env?.LOG_LEVEL) ??
    Logger._parseLogLevel(global?.LOG_LEVEL) ??
    Logger._parseLogLevel(window?.LOG_LEVEL) ??
    (process?.env?.NODE_ENV === "production" ? LogLevels.INFO : LogLevels.DEBUG)

  /**
   * Set Global Meta Data for Logger. The global meta data will only be included in
   * Loggers that are instantiated _after_ the meta data was set using this function.
   * Therefore it is recommended to put all Logger initialization into a `bootstrap.ts`
   * file and import this at the very beginning of your app or project, making sure
   * its code is executed before anything else.
   *
   * @param meta meta data
   */
  static setGlobalMeta(meta: Payload): void {
    Logger._globalMetaData = { ...meta }
  }

  /**
   * Like `JSON.stringify` but handles circular references and serializes error objects.
   */
  static stringify(value: any, space?: string | number | undefined): string {
    return JSON.stringify(value, Logger._serializeObj, space)
  }

  /**
   * Destroys circular references for use with JSON serialization
   *
   * @param from - Source object or array
   * @param seen - Array with object already serialized. Set to `[]` (empty array)
   *   when using this function!
   * @param scrub - If set, passwords and other sensitive data fields will be replaced by a placeholder and hidden from console or log files
   */
  private static _destroyCircular(
    from: any,
    seen: any[],
    scrub: boolean = false
  ) {
    let to: any
    if (Array.isArray(from)) {
      to = []
    } else {
      to = {}
    }

    seen.push(from)

    Object.keys(from).forEach((key) => {
      const value = from[key]

      if (
        typeof value === "string" &&
        (Logger.scrubValues.includes(
          key.toLowerCase().replace(/[^a-z0-9]/g, "")
        ) ||
          Logger._creditCardRegEx.test(value) ||
          value.startsWith("Bearer "))
      ) {
        // Looks like a sensitive value. Hide it from the logging endpoint
        to[key] = "[hidden]"
        return
      }

      if (typeof value === "function") {
        // No Logging of functions
        return
      }

      if (typeof value === "symbol") {
        // Use the symbol's name
        to[key] = value.toString()
        return
      }

      if (!value || typeof value !== "object") {
        // Simple data types
        to[key] = value
        return
      }

      if (typeof value === "object" && typeof value.toJSON === "function") {
        to[key] = value.toJSON()
        return
      }

      if (typeof value === "object" && value.constructor) {
        // Superagent/Axios includes a lot of detail information in the error object.
        // For the sake of readable logs, we remove all of that garbage here.
        const className = value.constructor.name
        if (Logger.collapseClasses.includes(className)) {
          to[key] = `[${className}]`
          return
        }
      }

      if (!seen.includes(from[key])) {
        to[key] = Logger._destroyCircular(from[key], seen.slice(0), scrub)
        return
      }

      to[key] = "[Circular]"
    })

    if (typeof from.name === "string") {
      to.name = from.name
    }

    if (typeof from.message === "string") {
      to.message = from.message
    }

    if (typeof from.stack === "string") {
      to.stack = from.stack
    }

    return to
  }

  /**
   * Helper function to serialize class instances to plain objects for logging
   *
   * @param key - Property key
   * @param value - Property value
   *
   * @example
   * const myObj = { foo: "bar" };
   * const str = JSON.stringify(myObj, serializeObj, "\t");
   */
  private static _serializeObj(key: any, value: any): any {
    if (typeof value === "object" && value !== null) {
      return Logger._destroyCircular(value, [])
    }
    return value
  }

  private static _parseLogLevel(
    value?: string | number | null
  ): LogLevels | undefined {
    const logLevelMap = {
      S: LogLevels.SILLY,
      D: LogLevels.DEBUG,
      I: LogLevels.INFO,
      W: LogLevels.WARN,
      E: LogLevels.ERROR,
      C: LogLevels.CRITICAL,
      N: LogLevels.NONE,
    }
    if (typeof value === "string") {
      const firstChar = value?.substr(0, 1).toUpperCase()
      const entry = Object.entries(logLevelMap).find(
        ([key]) => firstChar === key
      )
      return entry?.[1]
    } else if (typeof value === "number") {
      return (value >= LogLevels.SILLY && value <= LogLevels.CRITICAL) ||
        value === LogLevels.NONE
        ? value
        : undefined
    }
    return undefined
  }

  /** Metadata passed with each log line */
  meta: Payload
  /** Current log level; if `undefined` the default level is used */
  logLevel?: LogLevels

  private constructor(tag?: string, meta?: Payload, logLevel?: LogLevels) {
    if (logLevel) {
      this.logLevel = logLevel
    } else if (Logger.isNode) {
      this.logLevel = Logger._parseLogLevel(process.env.LOG_LEVEL)
    }

    let sanitizedTag = tag ?? "default"
    if (/\.(?:tsx?|jsx?)$/i.test(sanitizedTag)) {
      // Strip off unnecessary path information from the logger tag (e.g. if using __filename as tag)
      if (Logger.isNode && sanitizedTag.startsWith(process.cwd())) {
        sanitizedTag = sanitizedTag.replace(process.cwd(), "")
      }
      sanitizedTag = sanitizedTag.replace(
        /^(?:[/\\]?(?:src|dist|build|public)[/\\])?[/\\]?(.*?)\.(?:tsx?|jsx?)$/,
        "$1"
      )
    }

    this.meta = {
      ...Logger._globalMetaData,
      ...meta,
      tag: sanitizedTag,
    }
  }

  silly(message: string, payload?: Payload): Logger {
    return this._logInternal(LogLevels.SILLY, message, payload)
  }

  trace(message: string, payload?: Payload): Logger {
    return this._logInternal(LogLevels.SILLY, message, payload)
  }

  debug(message: string, payload?: Payload): Logger {
    return this._logInternal(LogLevels.DEBUG, message, payload)
  }

  info(message: string, payload?: Payload): Logger {
    return this._logInternal(LogLevels.INFO, message, payload)
  }

  warn(message: string, payload?: Payload): Logger {
    return this._logInternal(LogLevels.WARN, message, payload)
  }

  error(message: string, payload?: Payload): Logger
  error(message: string, error?: Error): Logger
  error(error: Error): Logger
  error(...args: [string, (Error | Payload)?] | [Error]): Logger {
    return this._logExceptionInternal(LogLevels.ERROR, ...args)
  }

  critical(message: string, payload?: Payload): Logger
  critical(message: string, error?: Error): Logger
  critical(error: Error): Logger
  critical(...args: [string, (Error | Payload)?] | [Error]): Logger {
    return this._logExceptionInternal(LogLevels.CRITICAL, ...args)
  }

  private _dispatchToHandlers(logEntry: LogEntry) {
    for (const handler of Logger._handlers) {
      handler(logEntry)
    }
  }

  /**
   * Write message to logs
   * @param level
   * @param logFunc
   * @param message
   * @param payloadRaw
   */
  private _logInternal(
    level: LogLevels,
    message: string,
    payloadRaw?: Payload
  ): Logger {
    const logLevel =
      this.logLevel ??
      Logger._parseLogLevel(global?.LOG_LEVEL) ??
      Logger._parseLogLevel(window?.LOG_LEVEL) ??
      Logger.defaultLevel
    if (!Logger.enabled || level < logLevel) {
      return this
    }

    const hasPayload = typeof payloadRaw !== "undefined" && payloadRaw !== null
    let payload: any = null
    try {
      // The Browser logger seems to have issues with circular references if no
      // debugger is attached. So we break all circular references here to be safe.
      payload = hasPayload
        ? Logger._destroyCircular(payloadRaw, [], true)
        : undefined
    } catch (error) {
      payload = `[${error.message}]`
    }

    this._dispatchToHandlers({
      timestamp: new Date(),
      level,
      message,
      payload,
      meta: this.meta,
    })

    return this
  }

  /**
   * Special handling for error objects
   *
   * @param level
   * @param logFunc
   * @param messageRaw
   * @param payloadRaw
   */
  private _logExceptionInternal(
    level: LogLevels,
    ...args: [string, (Error | Payload)?] | [Error]
  ): Logger {
    const logLevel =
      this.logLevel ??
      Logger._parseLogLevel(global?.LOG_LEVEL) ??
      Logger._parseLogLevel(window?.LOG_LEVEL) ??
      Logger.defaultLevel
    if (!Logger.enabled || level < logLevel) {
      return this
    }

    let message: string = ""
    let payload: Payload | undefined

    if (typeof args[0] === "string" || args[0] instanceof String) {
      message = args.splice(0, 1)[0] as string
    }

    if (args[0] instanceof Error) {
      const error = args[0]
      if (message.length === 0) {
        message = error.message
      }
      payload = { error }
    } else if (typeof args[0] === "object") {
      payload = { ...(args[0] as object) }
    }

    return this._logInternal(level, message, payload)
  }
}

/** Log output to interactive terminal in a human readable format and in colors (if supported) */
export function createTTYLogger(forceColor: boolean = false): LogHandlerFunc {
  // Colors see https://stackoverflow.com/questions/9781218/how-to-change-node-jss-console-font-color
  const logLevelColors = {
    [LogLevels.SILLY]: "\x1b[4m\x1b[2m\x1b[37m",
    [LogLevels.DEBUG]: "\x1b[4m\x1b[2m\x1b[37m",
    [LogLevels.INFO]: "\x1b[4m\x1b[1m\x1b[37m",
    [LogLevels.WARN]: "\x1b[4m\x1b[33m",
    [LogLevels.ERROR]: "\x1b[4m\x1b[31m",
    [LogLevels.CRITICAL]: "\x1b[41m\x1b[30m",
    [LogLevels.NONE]: "",
  }

  // Check if FORCE_COLOR environment variable is set
  const forceColorEnv = ["true", "on", "yes", "1"].includes(
    String(process?.env?.FORCE_COLOR).toLowerCase()
  )

  const supportsColor = (): boolean => {
    if (forceColor || forceColorEnv) {
      // Colors enforced in any case
      return true
    }

    if (Logger.isReactNative) {
      // In React Native we have no process.env but we most likely support colors in Expo console
      return true
    }

    if (!Logger.isNode) {
      // No colors if we aren't running in Node (as then we don't have `process` available)
      return false
    }

    if (!process.stdout?.isTTY) {
      // No colors if we have no interactive terminal
      return false
    }

    if (process.platform === "win32") {
      // A reasonably new Windows version should support colors
      return true
    }

    if (Logger.isCI) {
      // Most CI/CD platforms support colors as well
      return true
    }

    if (/-256(color)?$/i.test(process.env.TERM)) {
      return true
    }

    if (
      /^screen|^xterm|^vt100|^rxvt|color|ansi|cygwin|linux/i.test(
        process.env.TERM
      )
    ) {
      return true
    }

    if (process.env.COLORTERM) {
      return true
    }

    return false
  }

  const enableColors = supportsColor()

  // The payload is already sanitized so we can simply print it using `utils.inspect()` or `JSON.strigify()`:
  let stringify: (value: Payload) => string
  try {
    const util = require("util")
    stringify = (value) => util.inspect(value, false, null, enableColors)
  } catch (error) {
    stringify = (value) => JSON.stringify(value, null, 2)
  }

  return function log({ level, message, payload, meta }: LogEntry) {
    // Try to load `util` package. React Native requires you to install `util` manually using `npm i util --save`.
    const logFunc = ConsoleLogFuncs[level]
    if (enableColors) {
      const log = [
        `\x1b[35m[${meta?.tag}]`,
        logLevelColors[level] + LogLevelNames[level] + "\x1b[0m",
        `\x1b[37m${message}`,
      ].join(" ")
      if (payload) {
        logFunc(
          log,
          // Dim the output of the payload for better overall readability,
          "\x1b[2m\n" + stringify(payload) + "\x1b[0m"
        )
      } else {
        logFunc(log)
      }
    } else {
      const log = [`[${meta?.tag}]`, LogLevelNames[level], message].join(" ")
      if (payload) {
        logFunc(log, "\n" + stringify(payload))
      } else {
        logFunc(log)
      }
    }
  }
}

/** Log to Browser Console; Use colorful logs for Chome, Safari, etc. */
export function createBrowserLogger(): LogHandlerFunc {
  return function log({ level, message, payload, meta }: LogEntry) {
    const logFunc = ConsoleLogFuncs[level]
    if (payload && typeof console.groupCollapsed === "function") {
      console.groupCollapsed(
        `%c[${meta?.tag}] %c${message}`,
        "color:magenta;",
        "color:black;font-weight:normal"
      )
      logFunc(payload)
      console.groupEnd()
    } else if (payload) {
      logFunc(
        `%c[${meta?.tag}] %c${message}`,
        "color:magenta;",
        "color:black;",
        payload
      )
    } else {
      logFunc(`%c[${meta?.tag}] %c${message}`, "color:magenta;", "color:black;")
    }
  }
}

export function createJsonConsoleLogger() {
  return function log(logEntry: LogEntry) {
    const logFunc = ConsoleLogFuncs[logEntry.level]
    logFunc(
      JSON.stringify({
        ...logEntry,
        timestamp: logEntry.timestamp.toISOString(),
        level: LogLevelNames[logEntry.level],
      })
    ) // no need to break circular references anymore here
  }
}

/** Automatically chooses the "best" handler depending on whether we're running on a terminal, in a browser or in any other supported environment */
export function createDefaultLogger(forceColor?: boolean): LogHandlerFunc {
  const logTTY = createTTYLogger(forceColor)
  const logBrowser = createBrowserLogger()
  const logJson = createJsonConsoleLogger()

  return function log(logEntry: LogEntry) {
    if (
      Logger.isBrowser &&
      !Logger.isIE &&
      (!Logger.isReactNative || Logger.isReactNativeDebugger)
    ) {
      return logBrowser(logEntry)
    } else if (Logger.isBrowser || process.stdout?.isTTY) {
      return logTTY(logEntry)
    } else {
      return logJson(logEntry)
    }
  }
}

Logger.registerHandler(createDefaultLogger())

const WORKDIR = path.join(process.cwd(), "flatearth_adventure")

if (!fs.existsSync(WORKDIR)) {
  console.log(`ERROR: ${WORKDIR} does not exist.`)
  process.exit(1)
}
const configFilePath = path.join(WORKDIR, "settings.json")
if (!fs.existsSync(configFilePath)) {
  fs.writeFileSync(configFilePath, JSON.stringify(sampleConfig, undefined, 4))
}

const config: Config = JSON.parse(fs.readFileSync(configFilePath).toString())
const launcher = new Client()

const opts: ILauncherOptions = {
  clientPackage: null,
  authorization: Authenticator.getAuth(
    config.username,
    config.password || undefined
  ),
  root: WORKDIR,
  version: {
    number: "1.16.5",
    type: "release",
    custom: "fabric-loader-0.11.7-1.16.5",
  },
  memory: {
    max: "4G",
    min: "128M",
  },
}

launcher.launch(opts)

launcher.on("debug", (e) => console.log(e))
launcher.on("data", (e) => console.log(e))
