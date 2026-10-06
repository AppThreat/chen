package demo;

import java.io.IOException;
import java.util.AbstractMap;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;

/** Subtypes of JDK classes and interfaces: the hierarchy above them comes from the JDK. */
public class Registry<V> extends AbstractMap<String, V> implements AutoCloseable, Iterable<String> {
    private final Map<String, V> backing = new HashMap<>();

    public enum Scope { APP, SESSION }

    public static class RegistryException extends IOException {
        public RegistryException(String message) {
            super(message);
        }
    }

    @Override
    public Set<Entry<String, V>> entrySet() {
        return backing.entrySet();
    }

    @Override
    public V put(String key, V value) {
        return backing.put(key, value);
    }

    @Override
    public Iterator<String> iterator() {
        return backing.keySet().iterator();
    }

    public Callable<Integer> sizer() {
        return new Callable<Integer>() {
            @Override
            public Integer call() {
                return backing.size();
            }
        };
    }

    public Thread worker(Runnable task) {
        Thread t = new Thread(task, "registry-worker");
        t.setDaemon(true);
        return t;
    }

    @Override
    public void close() throws RegistryException {
        if (backing.isEmpty()) {
            throw new RegistryException("empty");
        }
        backing.clear();
    }
}
