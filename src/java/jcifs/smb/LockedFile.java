package jcifs.smb;

import java.io.IOException;

import java.util.Timer;
import java.util.TimerTask;

import jcifs.Config;

import smbdav.LockException;
import smbdav.Log;
import smbdav.MethodHandler;

/**
 * This is a big hack.  Basically, what we want to use is a singleton
 * <code>SmbFile</code>.  But when clients obtain an output stream
 * from that singleton, the resource is closed when the output stream is
 * closed, which effectively terminates the lock.  This class extends
 * <code>SmbFile</code> to ignore close requests; when <code>unlock()</code>
 * is called, the underlying resource is actually closed.  The end result
 * is the resource remains locked across all operations performed by the owner
 * of the lock, until the lock is removed via <code>unlock()</code>.
 *
 * @author Eric Glass
 */
public class LockedFile extends SmbFile {

    private static final long SMB_TIMEOUT =
            Config.getLong("jcifs.smb.client.soTimeout", 300000l);

    private static final Timer TIMER = new Timer(true);

    private static final int WRITE_OPTIONS = 0x0842;

    private TimerTask task;

    /**
     * Creates a <code>LockedFile</code> from the specified target resource.
     *
     * @param target The resource that is to be locked.
     * @throws IOException If an IO error occurs.
     * @throws LockException If the resource is already locked externally.
     */ 
    public LockedFile(SmbFile target) throws IOException, LockException {
        super(target, "", SmbFile.FILE_SHARE_READ);
        try {
            refresh();
        } catch (SmbException ex) {
            if (ex.getNtStatus() == NtStatus.NT_STATUS_SHARING_VIOLATION) {
                Log.log(Log.DEBUG,
                        "Resource {0} appears to be locked externally.", this);
                throw new LockException(MethodHandler.SC_LOCKED);
            }
            throw ex;
        }
        if (SMB_TIMEOUT < 20000l) {
            Log.log(Log.DEBUG, "SMB timeout is {0}; too short to refresh lock.",
                    new Long(SMB_TIMEOUT));
            return;
        }
        task = new TimerTask() {
            public void run() {
                try {
                    refresh();
                } catch (Exception ex) {
                    Log.log(Log.DEBUG, "Unable to refresh SMB lock on {0}: {1}",
                            new Object[] { LockedFile.this, ex });
                }
            }
        };
        // give 10 seconds leeway.
        TIMER.schedule(task, SMB_TIMEOUT - 10000l, SMB_TIMEOUT - 10000l);
    }

    /**
     * Unlocks the resource.
     *
     * @throws IOException If an IO error occurs.
     */ 
    public void unlock() throws IOException {
        synchronized (this) {
            if (task != null) task.cancel();
            task = null;
        }
        if (isOpen() == false) return;
        send(new SmbComClose(fid, 0l), new SmbComBlankResponse());
        opened = false;
    }

    void close(int f, long lastWriteTime) throws SmbException { }

    void close(long lastWriteTime) throws SmbException { }

    void close() throws SmbException { }

    private void refresh() throws IOException {
        open(SmbFile.O_CREAT | SmbFile.O_RDWR | SmbFile.O_APPEND,
                FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES, SmbFile.ATTR_NORMAL,
                        WRITE_OPTIONS);
    }

}
