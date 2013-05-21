package grith.jgrith.view.swing.proxyInit;

import javax.swing.JLabel;
import javax.swing.JPanel;

import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.FormSpecs;
import com.jgoodies.forms.layout.RowSpec;

public class ProxyInfoPanel extends JPanel {

	private JLabel subjectLabel;

	/**
	 * Create the panel
	 */
	public ProxyInfoPanel() {
		super();
		setLayout(new FormLayout(new ColumnSpec[] {
				FormSpecs.DEFAULT_COLSPEC, FormSpecs.RELATED_GAP_COLSPEC,
				FormSpecs.DEFAULT_COLSPEC }, new RowSpec[] {
				FormSpecs.DEFAULT_ROWSPEC, FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC }));
		add(getSubjectLabel(), new CellConstraints());
		//
	}

	/**
	 * @return the label
	 */
	protected JLabel getSubjectLabel() {
		if (subjectLabel == null) {
			subjectLabel = new JLabel();
			subjectLabel.setText("Subject");
		}
		return subjectLabel;
	}

}
