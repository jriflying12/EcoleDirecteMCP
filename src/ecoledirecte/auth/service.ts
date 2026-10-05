  return codes.length > 0
    ? codes
    : undefined;
}

function decodeBase64String(
  value: unknown,
): string {
  if (
    typeof value !==
      "string" ||
    value.length === 0
  ) {
    return "";
  }

  return Buffer.from(
    value,
    "base64",
  ).toString("utf-8");
}

function formatError(
  error: unknown,
): string {
  if (!(error instanceof Error)) {
    return String(error);
  }

  const message =
    formatSingleError(error);

  const cause =
    formatErrorCause(
      error.cause,
    );

  return cause &&
    cause !== message
    ? `${message} (${cause})`
    : message;
}

function formatSingleError(
  error: Error,
): string {
  if (
    error.name ===
    "TimeoutError"
  ) {
    return "Request timed out — the EcoleDirecte API did not respond in time";
  }

  const message =
    error.message.trim();

  return message.length > 0
    ? message
    : error.name;
}

function formatErrorCause(
  cause: unknown,
): string | undefined {
  if (
    cause instanceof Error
  ) {
    return formatSingleError(
      cause,
    );
  }

  if (
    !cause ||
    typeof cause !==
      "object"
  ) {
    return undefined;
  }

  const record =
    cause as Record<
      string,
      unknown
    >;

  const details = [
    typeof record.code ===
    "string"
      ? record.code
      : undefined,

    typeof record.hostname ===
    "string"
      ? record.hostname
      : undefined,

    typeof record.syscall ===
    "string"
      ? record.syscall
      : undefined,

    typeof record.message ===
      "string" &&
    record.message.trim().length > 0
      ? record.message.trim()
      : undefined,
  ].filter(
    (value): value is string =>
      Boolean(value),
  );

  return details.length > 0
    ? details.join(", ")
    : undefined;
}
