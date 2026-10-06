package demo;

/** Records and sealed types: java.lang.Record and ObjectMethods bootstrap from the JDK. */
public final class Shapes {
    private Shapes() {}

    public sealed interface Shape permits Circle, Square {}

    public record Circle(double radius) implements Shape {}

    public record Square(double side) implements Shape {}

    public static double area(Shape shape) {
        if (shape instanceof Circle c) {
            return Math.PI * c.radius() * c.radius();
        } else if (shape instanceof Square s) {
            return s.side() * s.side();
        }
        throw new IllegalArgumentException("unknown shape " + shape);
    }
}
