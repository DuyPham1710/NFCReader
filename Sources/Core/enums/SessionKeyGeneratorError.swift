enum SessionKeyGeneratorError: Error {
    case invalidKeySeedLength
    case hashTooShort
}
