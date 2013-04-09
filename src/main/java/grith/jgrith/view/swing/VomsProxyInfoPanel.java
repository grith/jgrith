package grith.jgrith.view.swing;

import grith.jgrith.control.CredentialStatusEvent;
import grith.jgrith.control.CredentialStatusListener;
import grith.jgrith.control.CredentialStatusTimerTask;
import grith.jgrith.vomsProxy.VomsProxy;

import java.util.Date;
import java.util.Timer;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.TitledBorder;

import org.globus.gsi.GlobusCredential;

import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.FormSpecs;
import com.jgoodies.forms.layout.RowSpec;

public class VomsProxyInfoPanel extends JPanel implements
CredentialStatusListener, ProxyInitListener {

	private static final String BORDER_DEFAULT_TITLE = "Status of current proxy";

	public static final String NO_VALID_PROXY_MESSAGE = "No valid proxy";
	public static final String NO_VO_PROXY = "None";
	public static final String NO_TIME_REMAINING = "None";
	public static final String ERROR_GETTING_VO_INFO = "Error retrieving VO info";

	private static String calculateIdentity(String dn) {

		int start = dn.toLowerCase().indexOf("cn=") + 3;
		int end = dn.toLowerCase().indexOf(",cn=proxy");
		if ((end == -1) || (end <= start)) {
			end = dn.length() - 1;
		}
		return dn.substring(start, end);
	}

	private GlobusCredential proxy = null;

	private VomsProxy vomsProxy = null;
	private Timer timer = null;

	private CredentialStatusTimerTask timerTask = null;
	private JButton detailsButton;
	private JTextField voTextField;
	private JTextField remainingTextField;
	private JTextField authenticatedTextField;
	private JTextField identityTextField;
	private JLabel label_3;
	private JLabel label_2;
	private JLabel label_1;

	private JLabel label;

	/**
	 * Create the panel
	 */
	public VomsProxyInfoPanel() {
		super();
		setBorder(BORDER_DEFAULT_TITLE);
		setLayout(new FormLayout(new ColumnSpec[] {
				FormSpecs.RELATED_GAP_COLSPEC, ColumnSpec.decode("65dlu"),
				FormSpecs.RELATED_GAP_COLSPEC,
				ColumnSpec.decode("default:grow(1.0)"),
				FormSpecs.RELATED_GAP_COLSPEC, FormSpecs.DEFAULT_COLSPEC,
				FormSpecs.RELATED_GAP_COLSPEC }, new RowSpec[] {
				FormSpecs.RELATED_GAP_ROWSPEC, FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC, FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC, FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC, FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC }));
		add(getLabel(), new CellConstraints(2, 2));
		add(getLabel_1(), new CellConstraints(2, 4));
		add(getLabel_2(), new CellConstraints(2, 6));
		add(getLabel_3(), new CellConstraints(2, 8));
		add(getIdentityTextField(), new CellConstraints(4, 2, 3, 1));
		add(getAuthenticatedTextField(), new CellConstraints(4, 4, 3, 1));
		add(getRemainingTextField(), new CellConstraints(4, 6, 3, 1));
		add(getVoTextField(), new CellConstraints(4, 8));
		add(getDetailsButton(), new CellConstraints(6, 8));
		//
		updateStatus();
	}

	@Override
	public void credentialStatusChanged(CredentialStatusEvent event) {

		if (event.getType() == CredentialStatusEvent.CREDENTIAL_EXPIRED) {
			timer.cancel();
			timer = null;
		}

		getRemainingTextField().setText(event.getStatus());
	}

	/**
	 * @return
	 */
	protected JTextField getAuthenticatedTextField() {
		if (authenticatedTextField == null) {
			authenticatedTextField = new JTextField();
			authenticatedTextField.setEditable(false);
		}
		return authenticatedTextField;
	}

	/**
	 * @return
	 */
	protected JButton getDetailsButton() {
		if (detailsButton == null) {
			detailsButton = new JButton();
			detailsButton.setText("Details");
		}
		return detailsButton;
	}

	/**
	 * @return
	 */
	protected JTextField getIdentityTextField() {
		if (identityTextField == null) {
			identityTextField = new JTextField();
			identityTextField.setEditable(false);
		}
		return identityTextField;
	}

	/**
	 * @return
	 */
	protected JLabel getLabel() {
		if (label == null) {
			label = new JLabel();
			label.setText("Identity");
		}
		return label;
	}

	/**
	 * @return
	 */
	protected JLabel getLabel_1() {
		if (label_1 == null) {
			label_1 = new JLabel();
			label_1.setText("Authenticated");
		}
		return label_1;
	}

	/**
	 * @return
	 */
	protected JLabel getLabel_2() {
		if (label_2 == null) {
			label_2 = new JLabel();
			label_2.setText("Time remaining");
		}
		return label_2;
	}

	/**
	 * @return
	 */
	protected JLabel getLabel_3() {
		if (label_3 == null) {
			label_3 = new JLabel();
			label_3.setText("Group");
		}
		return label_3;
	}

	/**
	 * @return
	 */
	protected JTextField getRemainingTextField() {
		if (remainingTextField == null) {
			remainingTextField = new JTextField();
			remainingTextField.setEditable(false);
		}
		return remainingTextField;
	}

	/**
	 * @return
	 */
	protected JTextField getVoTextField() {
		if (voTextField == null) {
			voTextField = new JTextField();
			voTextField.setEditable(false);
		}
		return voTextField;
	}

	@Override
	public void proxyCreated(GlobusCredential newProxy) {
		if (timer != null) {
			timer.cancel();
			timer = null;
		}
		this.proxy = newProxy;
		updateStatus();
	}

	@Override
	public void proxyDestroyed() {
		updateStatus();
	}

	public void setBorder(String title) {
		setBorder(new TitledBorder(null, title,
				TitledBorder.DEFAULT_JUSTIFICATION,
				TitledBorder.DEFAULT_POSITION, null, null));
	}

	private void setPlainProxyDetails() {
		getIdentityTextField().setToolTipText(proxy.getSubject());
		getIdentityTextField().setText(calculateIdentity(proxy.getSubject()));
		getAuthenticatedTextField().setText("Yes");

		if (timer == null) {
			timer = new Timer();
			timerTask = new CredentialStatusTimerTask(proxy);
			timerTask.addCredentialStatusListener(this);
			timer.schedule(timerTask, new Date(), 1000);
		}
	}

	private void setVomsProxyDetails() {

		String defaultFqan = vomsProxy.getDefaultFqan(false);
		if ((defaultFqan == null) || "".equals(defaultFqan)) {
			getVoTextField().setText(ERROR_GETTING_VO_INFO);
			getDetailsButton().setEnabled(false);
		}
		getVoTextField().setText(defaultFqan);
		getDetailsButton().setEnabled(false);
	}

	private void updateStatus() {

		try {
			proxy.verify();
		} catch (Exception e) {
			// means proxy is not valid anymore
			getIdentityTextField().setText(NO_VALID_PROXY_MESSAGE);
			getIdentityTextField().setToolTipText(null);
			getAuthenticatedTextField().setText("No");
			getRemainingTextField().setText(NO_TIME_REMAINING);
			getVoTextField().setText(NO_VO_PROXY);
			getDetailsButton().setEnabled(false);
			return;
		}

		setPlainProxyDetails();

		// now we try to make a voms proxy out of our credential
		try {
			vomsProxy = new VomsProxy(proxy);
		} catch (Exception e) {
			getVoTextField().setText(NO_VO_PROXY);
			getDetailsButton().setEnabled(false);
			return;
		}

		// nice, it's really a voms proxy
		setVomsProxyDetails();
	}

}
