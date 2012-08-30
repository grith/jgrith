package start;

import grith.jgrith.utils.CertificateFiles;
import grith.jgrith.utils.VomsesFiles;
import grith.jgrith.view.swing.MyProxyUpAndDownloadPanel;
import grith.jgrith.view.swing.VomsProxyInfoAndInitPanel;

import java.awt.BorderLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.JFrame;
import javax.swing.JMenuBar;
import javax.swing.JPanel;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.jgoodies.forms.factories.FormFactory;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.RowSpec;

public class VomsProxyInit {

	/**
	 * Launch the
	 * application...
	 * 
	 * @param args
	 */
	public static void main(String args[]) {
		try {
			System.setProperty("apple.laf.useScreenMenuBar", "true");

			try {
				VomsesFiles.copyVomses(null);
				CertificateFiles.copyCACerts(true);
			} catch (Exception e) {
				myLogger.error("Could not copy ca certs: "
						+ e.getLocalizedMessage());
			}
			VomsProxyInit window = new VomsProxyInit();

			window.enableWriteToDisk(true);
			window.frame.setVisible(true);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private MyProxyUpAndDownloadPanel myProxyUpAndDownloadPanel;

	static final Logger myLogger = LoggerFactory.getLogger(VomsProxyInit.class
			.getName());
	private MyProxyUpAndDownloadPanel myProxyPanel;
	private JPanel panel;
	private VomsProxyInfoAndInitPanel vomsProxyInfoAndInitPanel;

	private JFrame frame;

	/**
	 * Create the application
	 */
	public VomsProxyInit() {
		initialize();
	}

	protected void createMenus(JMenuBar mb) {
		if (System.getProperty("mrj.version") == null) {
			// later
		} else {

		}
	}

	/**
	 * If you call this method with true, every proxy that is created with the
	 * panel is stored to the default globus location.
	 * 
	 * It probably makes sense to leave that (false) and manage the writing of
	 * the proxy on your own.
	 * 
	 * @param write
	 *            whether to write a created proxy to disk (true) or not (false
	 *            -- default)
	 */
	public void enableWriteToDisk(boolean write) {
		getVomsProxyInfoAndInitPanel().enableWriteToDisk(write);
	}

	/**
	 * @return
	 */
	protected MyProxyUpAndDownloadPanel getMyProxyPanel() {
		if (myProxyPanel == null) {
			myProxyPanel = new MyProxyUpAndDownloadPanel();
		}
		return myProxyPanel;
	}

	/**
	 * @return
	 */
	protected JPanel getPanel() {
		if (panel == null) {
			panel = new JPanel();
			panel.setLayout(new FormLayout(new ColumnSpec[] {
					FormFactory.RELATED_GAP_COLSPEC,
					ColumnSpec.decode("312px:grow(1.0)"),
					FormFactory.RELATED_GAP_COLSPEC }, new RowSpec[] {
					FormFactory.RELATED_GAP_ROWSPEC,
					RowSpec.decode("271px:grow(1.0)"),
					FormFactory.RELATED_GAP_ROWSPEC, RowSpec.decode("default"),
					FormFactory.RELATED_GAP_ROWSPEC }));
			panel.add(getVomsProxyInfoAndInitPanel(), new CellConstraints(
					"2, 2, fill, fill"));
			panel.add(getMyProxyPanel(), new CellConstraints(2, 4));
			// panel.add(getMyProxyUpAndDownloadPanel(), new CellConstraints(2,
			// 4));
			getVomsProxyInfoAndInitPanel().addProxyListener(getMyProxyPanel());
			getMyProxyPanel().addProxyListener(getVomsProxyInfoAndInitPanel());
			getVomsProxyInfoAndInitPanel().loadPossibleLocalProxy();
		}
		return panel;
	}

	/**
	 * @return
	 */
	protected VomsProxyInfoAndInitPanel getVomsProxyInfoAndInitPanel() {
		if (vomsProxyInfoAndInitPanel == null) {
			vomsProxyInfoAndInitPanel = new VomsProxyInfoAndInitPanel();
		}
		return vomsProxyInfoAndInitPanel;
	}

	/**
	 * Initialize the contents of the frame
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setTitle("Voms proxy tool");
		frame.setLocation(100, 100);
		frame.addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(final WindowEvent e) {
				System.exit(0);
			}
		});
		frame.setBounds(100, 100, 474, 447);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().add(getPanel(), BorderLayout.CENTER);
	}

	/**
	 * Sets the combobox that displays lifetimes
	 * 
	 * @param lifetimes
	 *            a preselection of lifetimes
	 */
	public void setLifetimeDefaults(Integer[] lifetimes) {
		getVomsProxyInfoAndInitPanel().setLifetimeDefaults(lifetimes);
	}

}
