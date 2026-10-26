final class Unsafe {
    private Unsafe() {}

    static Process runUserCommand(String command) throws java.io.IOException {
        return Runtime.getRuntime().exec(command);
    }
}
