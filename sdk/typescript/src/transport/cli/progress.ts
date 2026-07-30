const REFRESH_MILLISECONDS = 1_000;
const HIDE_CURSOR = "\u001B[?25l";
const SHOW_CURSOR = "\u001B[?25h";

export interface ProgressWritable {
  readonly isTTY?: boolean;
  write(value: string): unknown;
}

export interface ProgressClock {
  now(): number;
  setInterval(callback: () => void, milliseconds: number): NodeJS.Timeout;
  clearInterval(timer: NodeJS.Timeout): void;
}

const DEFAULT_CLOCK: ProgressClock = {
  now: Date.now,
  setInterval: (callback, milliseconds) => setInterval(callback, milliseconds),
  clearInterval: (timer) => clearInterval(timer),
};

export class Progress {
  readonly #stream: ProgressWritable;
  readonly #clock: ProgressClock;
  readonly #startedAt: number;
  readonly #enabled: boolean;
  #timer: NodeJS.Timeout | null = null;
  #timerLineActive = false;
  #cursorHidden = false;

  public constructor(
    stream: ProgressWritable = process.stderr,
    clock: ProgressClock = DEFAULT_CLOCK,
    interactive = true,
  ) {
    this.#stream = stream;
    this.#clock = clock;
    this.#startedAt = clock.now();
    this.#enabled = interactive;
  }

  public get interactive(): boolean {
    return this.#enabled && this.#stream.isTTY === true;
  }

  public get elapsedSeconds(): number {
    return Math.max(
      0,
      Math.floor((this.#clock.now() - this.#startedAt) / 1_000),
    );
  }

  public stage(message: string): void {
    this.#stream.write(`${this.#line(message)}\n`);
  }

  public startTimer(message: string): void {
    if (!this.interactive) {
      this.stage(message);
      return;
    }
    this.#stream.write(HIDE_CURSOR);
    this.#cursorHidden = true;
    this.#renderTimer(message);
    this.#timer = this.#clock.setInterval(
      () => this.#renderTimer(message),
      REFRESH_MILLISECONDS,
    );
  }

  public stopTimer(): void {
    if (this.#timer !== null) {
      this.#clock.clearInterval(this.#timer);
      this.#timer = null;
    }
    if (this.#timerLineActive) {
      this.#stream.write("\n");
      this.#timerLineActive = false;
    }
    if (this.#cursorHidden) {
      this.#stream.write(SHOW_CURSOR);
      this.#cursorHidden = false;
    }
  }

  #line(message: string): string {
    const elapsedSeconds = this.elapsedSeconds;
    const minutes = Math.floor(elapsedSeconds / 60);
    const seconds = elapsedSeconds % 60;
    return `[${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}] ${message}`;
  }

  #renderTimer(message: string): void {
    this.#stream.write(
      `${this.#timerLineActive ? "\r" : ""}${this.#line(message)}`,
    );
    this.#timerLineActive = true;
  }
}
