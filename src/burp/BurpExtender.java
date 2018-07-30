package burp;

import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Image;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.font.TextAttribute;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import javax.swing.BorderFactory;
import javax.swing.DefaultComboBoxModel;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.border.TitledBorder;
/**
 * The Burp Extension for Qualys WAS.
 * It allows to seamlessly push Burp scanner findings into WAS versus the current 
 * tedious method of exporting an XML file and then importing the file in WAS.
 *
 */
public class BurpExtender
  implements IBurpExtender, ITab, IExtensionStateListener, IContextMenuFactory, ActionListener 
{
  private IBurpExtenderCallbacks callbacks;
  private IScanIssue[] scanIssues = null;
  private JSplitPane splitPane;
  private JTextField username_field;
  private JPasswordField password_field;
  private JTextField username_field_tab = new JTextField(25);
  private JPasswordField password_field_tab = new JPasswordField(25);
  private JComboBox<String> qualysPortal_URI_list_tab;
  private int portalSelectedIndex;
  
  private String username_login;
  private char[] password_login;
  
  private JTextField qualys_portal_textfield_onexportPanel;
  private JLabel webAppURLLabel;
  private JComboBox<String> webapplication_list_combox;
  private JComboBox<String> qualysPortal_URI_list;
  private JCheckBox purgeIssues;
  private JCheckBox closeIssues;
  
  private List<String> webapplistsLabel = new ArrayList<String>();
   
  private JScrollPane logPane;
  private static JPanel upperPanel;
  private static JPanel lowerPanel;
  public static JTextArea logTextArea = new JTextArea("");
  
  private JButton refresh;
 
  private String searchWebappsURL;
  private String importBurpURL;
  private GridBagConstraints constraints;
  private JPanel loginPanel;
  private JPanel buttonsPanel;
  private JPanel exportBurpFilePanel;
      
  private JFrame frame= new JFrame("Qualys Import Settings");  
  private static JLabel webappid_label = new JLabel("Web App Name (Select the Web application associated with these issues) : ");
 
  private JLabel authenticationLabel = new JLabel();
  private JLabel authenticationLabelInTab = new JLabel();
  private JLabel exportStatusLabel = new JLabel();
  private JLabel failedExportStatusLabel = new JLabel();
  
  private JLabel processing;
  private JLabel processingInTab;
  
  private JTextField pcpURLInTab; // private cloud platform
  private JTextField pcpURL;
  private JLabel pcpURLLabelInTab;
  private String qualysPlatformURL;
  
  private WASSearch wasSearchRequest;
  private ArrayList<WebAppItem> webappLists;
  
  public static StringBuilder logBuilder = new StringBuilder();
  private SimpleDateFormat time_formatter = new SimpleDateFormat("yyyy-MM-dd_HH:mm:ss.SSS");
  
  private static final String PCP = "Private Cloud Platform";
  
  private static final String[] QUALYS_Portal_Name_List = { "US Platform 1", "US Platform 2", "US Platform 3", "EU Platform 1", 
    "EU Platform 2", "India Platform", PCP };
  
  private static String searchApiPath = "/qps/rest/3.0/search/was/webapp";
  private static String importApiPath = "/qps/rest/3.0/import/was/burp";
  
  private static final String[] QUALYS_Portal_Webapp_List = { "https://qualysapi.qualys.com/qps/rest/3.0/search/was/webapp", 
    "https://qualysapi.qg2.apps.qualys.com/qps/rest/3.0/search/was/webapp", 
    "https://qualysapi.qg3.apps.qualys.com/qps/rest/3.0/search/was/webapp", 
    "https://qualysapi.qualys.eu/qps/rest/3.0/search/was/webapp", 
    "https://qualysapi.qg2.apps.qualys.eu/qps/rest/3.0/search/was/webapp", 
    "https://qualysapi.qg1.apps.qualys.in/qps/rest/3.0/search/was/webapp",
    PCP
    };
  
  private static final String[] QUALYS_Portal_ImportBurp_URL = { "https://qualysapi.qualys.com/qps/rest/3.0/import/was/burp", 
    "https://qualysapi.qg2.apps.qualys.com/qps/rest/3.0/import/was/burp", 
    "https://qualysapi.qg3.apps.qualys.com/qps/rest/3.0/import/was/burp", 
    "https://qualysapi.qualys.eu/qps/rest/3.0/import/was/burp", 
    "https://qualysapi.qg2.apps.qualys.eu/qps/rest/3.0/import/was/burp", 
    "https://qualysapi.qg1.apps.qualys.in/qps/rest/3.0/import/was/burp",
    PCP
    };
  
  
  private static final String Extension_Name = "Qualys WAS";
  private static final String Authentication_Fail_Error_Message = "Authentication Failed! Please try again.";
  private static final String Export_XML_File_Fail_Error_Message = "Export to WAS failed. Please check Logs on the Qualys WAS tab for details.";
  private static final String Login_Successful_Message = "Credentials Validated Successfully!";
  private static final String Empty_Login_UserName_InputField_Error_Message = "Error: Username field is empty, request can not be processed";
  private static final String Empty_Login_Password_InputField_Error_Message = "Error: Password field is empty, request can not be processed";
  private static final String Empty_Platform_URL_InputField_Error_Message = "Error: Qualys API Server base URL field is empty, request can not be processed";
  private static final String PURGE_BURP_ISSUES_TOOLTIP_TEXT = "If option is checked, all previous issues for the web application will be removed before import report issues.\n" + 
		"Recommended to avoid duplicate findings when you are importing from multiple Burp instances.";
  private static final String CLOSE_EXISTING_ISSUES_TOOLTIP_TEXT = "If option is checked, existing issues not reported in this report will be marked as Fixed.";
  
  public BurpExtender() {}
  
public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
	URL url= this.getClass().getClassLoader().getResource("resources/logo.png");
	ImageIcon imgicon = new ImageIcon(url);
	frame.setIconImage(imgicon.getImage());
	
	ArrayList<JMenuItem> menu = new ArrayList<JMenuItem>();
     byte ctx = invocation.getInvocationContext();
     // Only show context menu for scanner results...
     if (ctx == IContextMenuInvocation.CONTEXT_SCANNER_RESULTS) {
         this.scanIssues = invocation.getSelectedIssues();
         ImageIcon imageIcon = new ImageIcon(url);
         Image image = imageIcon.getImage(); // transform it 
         Image newimg = image.getScaledInstance(13, 20,  java.awt.Image.SCALE_SMOOTH); // scale it the smooth way  
         imageIcon = new ImageIcon(newimg);  // transform it back
         
         JMenuItem item = new JMenuItem("Send to Qualys WAS", imageIcon);
         item.addActionListener(this);
         menu.add(item);
     }
     return menu;
}


public void actionPerformed(ActionEvent e) {
	if (username_login == null || password_login == null) {
		showLoginWizard();
	}else {
		paintNextPageInWizard(webappLists);
	}
}

 public void showLoginWizard() {
	    //For context-menu
	
	 	frame.getContentPane().removeAll();
		frame.setLayout(new FlowLayout());
		
		loginPanel = new JPanel(new GridBagLayout());
		constraints = new GridBagConstraints();
	    constraints.anchor = 17;
	    constraints.insets = new Insets(10, 10, 10, 10);
		
	    loginPanel.setPreferredSize(new Dimension(580,450));
		
	    JLabel username_label = new JLabel("Qualys Username : ");
	    JLabel password_label = new JLabel("Qualys Password  : ");
	    JLabel qualys_Portal_URL_Label = new JLabel("Qualys Portal Platform URL : ");
	   
	    
	    constraints.gridx = 0;
	    constraints.gridy = 2;
		qualys_Portal_URL_Label.setForeground(Color.DARK_GRAY);
	    qualys_Portal_URL_Label.setFont(new Font(username_label.getFont().getFamily(), 1, 13));
		loginPanel.add(qualys_Portal_URL_Label, constraints);
		
		qualysPortal_URI_list = new JComboBox<String>(QUALYS_Portal_Name_List);   
		qualysPortal_URI_list.setPreferredSize(new Dimension(225, 30));
		constraints.gridx = 1;
		loginPanel.add(qualysPortal_URI_list, constraints);
		
		JLabel whatsMyPlatform = new JLabel("What's my platform?");
		whatsMyPlatform.setFont(new Font("Courier New", 1, 11));
		Font font = whatsMyPlatform.getFont();
		Map attributes = font.getAttributes();
		attributes.put(TextAttribute.UNDERLINE, TextAttribute.UNDERLINE_ON);
		whatsMyPlatform.setFont(font.deriveFont(attributes));
		whatsMyPlatform.setForeground(Color.blue);
		whatsMyPlatform.setCursor(new Cursor(Cursor.HAND_CURSOR));
		whatsMyPlatform.setMinimumSize(whatsMyPlatform.getPreferredSize());
		whatsMyPlatform.addMouseListener(new MouseAdapter() {
	            @Override
	            public void mouseClicked(MouseEvent e) {
	                try {
	                    Desktop.getDesktop().browse(new URI("https://community.qualys.com/docs/DOC-4172"));
	                } catch (Exception ex) {
	                    //It looks like there's a problem
	                }
	            }
	        });
	   
		constraints.gridx = 1;
	    constraints.gridy = 3;
	    constraints.anchor = GridBagConstraints.NORTHEAST;
		loginPanel.add(whatsMyPlatform, constraints);
	
		JLabel pcpURLLabel = new JLabel("Qualys API server base URL : ");
		constraints.gridx = 0;
	    constraints.gridy = 4;
	    pcpURLLabel.setFont(new Font(username_label.getFont().getFamily(), 1, 13));
	    pcpURLLabel.setForeground(Color.DARK_GRAY);
		pcpURL = new JTextField(25);
		pcpURLLabel.setVisible(false);
		pcpURL.setVisible(false);
		
		loginPanel.add(pcpURLLabel, constraints);
		
		constraints.gridx = 1;
		loginPanel.add(pcpURL, constraints);
		
		
		qualysPortal_URI_list.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				if (qualysPortal_URI_list.getSelectedIndex() != -1) {
					String url = QUALYS_Portal_Name_List[qualysPortal_URI_list.getSelectedIndex()];
					if (url.equals(PCP)) {
						pcpURL.setVisible(true);
						pcpURLLabel.setVisible(true);
					}else {
						pcpURLLabel.setVisible(false);
						pcpURL.setVisible(false);
					}
				}
				
			}
		});
				
		constraints.gridx = 0;
	    constraints.gridy = 5;
		username_label.setFont(new Font(username_label.getFont().getFamily(), 1, 13));
	    username_label.setForeground(Color.DARK_GRAY);
		username_field = new JTextField(25);
		loginPanel.add(username_label, constraints);
		
		constraints.gridx = 1;
		loginPanel.add(username_field, constraints);
			
		constraints.gridx = 0;
	    constraints.gridy = 6;
		password_label.setForeground(Color.DARK_GRAY);
	    password_label.setFont(new Font(username_label.getFont().getFamily(), 1, 13));
		password_field = new JPasswordField(25);
		loginPanel.add(password_label, constraints);
		
		constraints.gridx = 1;
		loginPanel.add(password_field, constraints);
		 			
		JButton loginButton = new JButton("Validate Credentials");
	    loginButton.addActionListener(new ValidateCredsActionListener(true)); 
	    constraints.gridx = 1;
	    constraints.gridy = 7;
	    constraints.anchor = GridBagConstraints.WEST;
	    loginPanel.add(loginButton, constraints);
		
	    constraints.gridx = 0;
	    constraints.gridy = 8;
	    URL urlGif= this.getClass().getClassLoader().getResource("resources/spinner.gif");
		ImageIcon imgiconGif = new ImageIcon(urlGif);
		Image imgGif = imgiconGif.getImage() ;  
		 
		imgiconGif = new ImageIcon( imgGif );	
	    processing = new JLabel("Processing...", imgiconGif, JLabel.CENTER);
	    processing.setVisible(false);
	    loginPanel.add(processing, constraints);
	    	    
		constraints.gridx = 0;
	    constraints.gridy = 9;
	    constraints.gridwidth = GridBagConstraints.REMAINDER;
	    authenticationLabel.setVisible(false);
	    loginPanel.add(authenticationLabel, constraints);

	    TitledBorder loginBorder = new TitledBorder("Login Credentials");
	    loginBorder.setTitleJustification(TitledBorder.LEFT);
	    loginBorder.setTitlePosition(TitledBorder.TOP);
		
	    loginPanel.setBorder(loginBorder);
	    
	    frame.getContentPane().add(loginPanel);  
	     
	    frame.pack();
	    frame.setLocationRelativeTo(upperPanel);
	    frame.setVisible(true);
 }
  
 
  public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
  {
    this.callbacks = callbacks;
    callbacks.setExtensionName(Extension_Name);
    callbacks.registerContextMenuFactory(this);
    SwingUtilities.invokeLater(new Runnable()
    {
      public void run()
      {
        splitPane = new JSplitPane(0);
        
        int dividerLocation_Vertical = new Double(0.65*Toolkit.getDefaultToolkit().getScreenSize().height).intValue();
        
        splitPane.setDividerLocation(dividerLocation_Vertical);
        upperPanel = new JPanel(new GridBagLayout());
        lowerPanel = new JPanel(new GridLayout(1, 1));

        logPane = new JScrollPane(logTextArea);
    
        BurpExtender.this.buildLoginPanel();
   
        BurpExtender.upperPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), "Enter Qualys Subscription Details"));
        logPane.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), "Logs"));
      
        splitPane.add(upperPanel);
        splitPane.add(lowerPanel);
        upperPanel.add(loginPanel);
        lowerPanel.add(logPane);

        callbacks.customizeUiComponent(splitPane);
        callbacks.customizeUiComponent(upperPanel);
        callbacks.customizeUiComponent(logPane);
        callbacks.customizeUiComponent(lowerPanel);
       
        callbacks.addSuiteTab(BurpExtender.this);
      }
    });
  }
  


  public String getTabCaption()
  {
    return Extension_Name;
  }
  

  public Component getUiComponent()
  {
    return splitPane;
  }

  private void buildLoginPanel()
  {
    loginPanel = new JPanel(new GridBagLayout());
    loginPanel.setPreferredSize(new Dimension(535,400));
    constraints = new GridBagConstraints();
    constraints.anchor = 17;
    constraints.insets = new Insets(10, 10, 10, 10);
   
    JLabel username_label = new JLabel("Qualys Username  : ");
    JLabel password_label = new JLabel("Qualys Password    : ");
    JLabel qualys_Portal_URL_Label = new JLabel("Qualys Portal Platform : ");
    
    qualysPortal_URI_list_tab = new JComboBox<String>(QUALYS_Portal_Name_List);
    
    qualysPortal_URI_list_tab.setPreferredSize(new Dimension(225, 30));
    
    JButton loginButton = new JButton("Validate Credentials");
    loginButton.addActionListener(new ValidateCredsActionListener(false));
    
    JButton clearButton = new JButton("Clear Settings ");
    clearButton.addActionListener(new ActionListener() {
		
		@Override
		public void actionPerformed(ActionEvent e) {
			username_field_tab.setText("");
			password_field_tab.setText("");
			username_login = null;
			password_login = null;
			qualysPlatformURL = null;
			pcpURLInTab.setText("");;
			authenticationLabelInTab.setVisible(false);
			logTextArea.setText("");
			logBuilder.delete(0, logBuilder.length());
			wasSearchRequest = null;
			processingInTab.setVisible(false);
			
		}
	});
  
    constraints.gridx = 0;
    constraints.gridy = 2;
    loginPanel.add(qualys_Portal_URL_Label, constraints);
    qualys_Portal_URL_Label.setForeground(Color.DARK_GRAY);
    qualys_Portal_URL_Label.setFont(new Font(username_label.getFont().getFamily(), 1, 13));
    
    constraints.gridx = 1;
    loginPanel.add(qualysPortal_URI_list_tab, constraints);
    
    
    JLabel whatsMyPlatform = new JLabel("What's my platform?");
	whatsMyPlatform.setFont(new Font("Courier New", 1, 11));
	Font font = whatsMyPlatform.getFont();
	Map attributes = font.getAttributes();
	attributes.put(TextAttribute.UNDERLINE, TextAttribute.UNDERLINE_ON);
	whatsMyPlatform.setFont(font.deriveFont(attributes));
	whatsMyPlatform.setForeground(Color.blue);
	whatsMyPlatform.setCursor(new Cursor(Cursor.HAND_CURSOR));
	whatsMyPlatform.setMinimumSize(whatsMyPlatform.getPreferredSize());
	whatsMyPlatform.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                try {
                    Desktop.getDesktop().browse(new URI("https://community.qualys.com/docs/DOC-4172"));
                } catch (Exception ex) {
                    //It looks like there's a problem
                }
            }
        });
   
	constraints.gridx = 1;
    constraints.gridy = 3;
    constraints.anchor = GridBagConstraints.NORTHEAST;
	loginPanel.add(whatsMyPlatform, constraints);
	
	pcpURLLabelInTab = new JLabel("Qualys API Server base URL : ");
	constraints.gridx = 0;
    constraints.gridy = 4;
    pcpURLLabelInTab.setFont(new Font(username_label.getFont().getFamily(), 1, 13));
    pcpURLLabelInTab.setForeground(Color.DARK_GRAY);
	pcpURLInTab = new JTextField(25);
	pcpURLLabelInTab.setVisible(false);
	pcpURLInTab.setVisible(false);
	
	loginPanel.add(pcpURLLabelInTab, constraints);
	
	constraints.gridx = 1;
	loginPanel.add(pcpURLInTab, constraints);
	
	
	qualysPortal_URI_list_tab.addActionListener(new ActionListener() {
		
		@Override
		public void actionPerformed(ActionEvent e) {
			if (qualysPortal_URI_list_tab.getSelectedIndex() != -1) {
				String url = QUALYS_Portal_Name_List[qualysPortal_URI_list_tab.getSelectedIndex()];
				if (url.equals(PCP)) {
					pcpURLInTab.setVisible(true);
					pcpURLLabelInTab.setVisible(true);
				}else {
					pcpURLLabelInTab.setVisible(false);
					pcpURLInTab.setVisible(false);
				}
			}
			
		}
	});
	
    
    constraints.gridx = 0;
    constraints.gridy = 5;
    
    username_label.setFont(new Font(username_label.getFont().getFamily(), 1, 13));
    username_label.setForeground(Color.DARK_GRAY);
    loginPanel.add(username_label, constraints);
    
    constraints.gridx = 1;
    loginPanel.add(username_field_tab, constraints);
    
    constraints.gridx = 0;
    constraints.gridy = 6;
    loginPanel.add(password_label, constraints);
    password_label.setForeground(Color.DARK_GRAY);
    password_label.setFont(new Font(username_label.getFont().getFamily(), 1, 13));
    

    constraints.gridx = 1;
    loginPanel.add(password_field_tab, constraints);
		    
    
    
    constraints.gridx = 1;
    constraints.gridy = 7;
    constraints.anchor = GridBagConstraints.WEST;
    loginPanel.add(loginButton, constraints);
    
    constraints.gridx = 0;
    constraints.gridy = 7;
    constraints.anchor = GridBagConstraints.EAST;
    loginPanel.add(clearButton, constraints);
    
    constraints.anchor = GridBagConstraints.CENTER;
    
	URL urlGif= this.getClass().getClassLoader().getResource("resources/spinner.gif");
	ImageIcon imgiconGif = new ImageIcon(urlGif);
	Image imgGif = imgiconGif.getImage() ;  
	 
	imgiconGif = new ImageIcon( imgGif );	
	processingInTab = new JLabel("Processing...", imgiconGif, JLabel.CENTER);
	
	
	constraints.gridx = 0;
    constraints.gridy = 8;
    constraints.gridwidth = GridBagConstraints.REMAINDER;
    processingInTab.setVisible(false);
    loginPanel.add(processingInTab, constraints);
	
    constraints.gridx = 0;
    constraints.gridy = 9;
    constraints.gridwidth = GridBagConstraints.REMAINDER;
    authenticationLabelInTab.setVisible(false);
    loginPanel.add(authenticationLabelInTab, constraints);
    
    TitledBorder loginBorder = new TitledBorder("Login Credentials");
    loginBorder.setTitleJustification(TitledBorder.LEFT);
    loginBorder.setTitlePosition(TitledBorder.TOP);
    
    loginPanel.setBorder(loginBorder);    
    
  }
  
  private void buildConfigPanel() {

	  	
	    frame.setLayout(new GridBagLayout());
	    exportBurpFilePanel = new JPanel(new GridBagLayout());
	    exportBurpFilePanel.setPreferredSize(new Dimension(590,400));
	    constraints = new GridBagConstraints();
	    constraints.anchor = 17;
	    constraints.insets = new Insets(10, 10, 10, 10);
	   
	    
	    webapplication_list_combox = new JComboBox<String>();
	    webapplication_list_combox.setFont(new Font(webappid_label.getFont().getFamily(), 0, 12));
	    webapplication_list_combox.setPreferredSize(new Dimension (360, 25));
	    webapplication_list_combox.setAutoscrolls(true);
		
	    qualys_portal_textfield_onexportPanel = new JTextField(39);
	    qualys_portal_textfield_onexportPanel.setMinimumSize(qualys_portal_textfield_onexportPanel.getPreferredSize());
	    
	    if(QUALYS_Portal_Name_List[portalSelectedIndex].equals(PCP )) {
	    	qualys_portal_textfield_onexportPanel.setText(QUALYS_Portal_Name_List[portalSelectedIndex]+" - " + qualysPlatformURL);
	    } else {
	    	qualys_portal_textfield_onexportPanel.setText(QUALYS_Portal_Name_List[portalSelectedIndex]);
	    }
	    qualys_portal_textfield_onexportPanel.setEditable(false);
	    JButton sendButton = new JButton("Send to Qualys WAS ");
	    sendButton.setFont(new Font(webappid_label.getFont().getFamily(), 1, 10));
	    sendButton.addActionListener(new ExportFileButtonActionListener());
	 
	    
	    JLabel qualys_Portal_URL_Label = new JLabel("Qualys Portal Platform : ");
	    constraints.gridx = 0;
	    constraints.gridy = 0;
	    qualys_Portal_URL_Label.setForeground(Color.DARK_GRAY);
	    qualys_Portal_URL_Label.setFont(new Font(webappid_label.getFont().getFamily(), 1, 12));
	    exportBurpFilePanel.add(qualys_Portal_URL_Label, constraints);
	    
	    constraints.gridx = 0;
	    constraints.gridy = 1;
	    qualys_portal_textfield_onexportPanel.setVisible(true);
	    exportBurpFilePanel.add(qualys_portal_textfield_onexportPanel, constraints);   
	    
	    constraints.gridx = 0;
	    constraints.gridy = 2;
	    constraints.weightx = 1;
	  
	    constraints.anchor = GridBagConstraints.FIRST_LINE_START;
	    webappid_label.setForeground(Color.DARK_GRAY);
	    webappid_label.setFont(new Font(webappid_label.getFont().getFamily(), 1, 12));
	    exportBurpFilePanel.add(webappid_label, constraints);
	    
	  
	    constraints.gridx = 0;
	    constraints.gridy = 3;
	   
	    refresh = new JButton();
	    URL url= this.getClass().getClassLoader().getResource("resources/refresh.png");
		ImageIcon imgicon = new ImageIcon(url);
		Image img = imgicon.getImage() ;  
		Image newimg = img.getScaledInstance( 15, 15,  java.awt.Image.SCALE_SMOOTH ) ;  
		imgicon = new ImageIcon( newimg );		
		refresh.setIcon(imgicon);
		
		refresh.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				refreshWebAppsList();
				
			}
		});
		
		constraints.anchor = GridBagConstraints.FIRST_LINE_START;
	    
	    JPanel webAppRefresh = new JPanel(new FlowLayout(FlowLayout.LEFT));
	    webAppRefresh.setPreferredSize(new Dimension(450, 30));
	    webAppRefresh.add(webapplication_list_combox);
	    webAppRefresh.add(refresh);
	    
	    exportBurpFilePanel.add(webAppRefresh, constraints);
	    
	    webAppURLLabel = new JLabel();
	    webAppURLLabel.setMinimumSize(webAppURLLabel.getPreferredSize());
	    webAppURLLabel.setFont(new Font(webappid_label.getFont().getFamily(), 0, 11));
	    
	    
	    
	    constraints.gridx = 0;
	    constraints.gridy = 4;
	    constraints.weightx = 1;
	    constraints.gridwidth = 2;
	    constraints.anchor = GridBagConstraints.FIRST_LINE_START;	    
	    exportBurpFilePanel.add(webAppURLLabel, constraints);
	    
	    constraints.gridx = 0;
	    constraints.gridy = 5;
	    constraints.weightx = 1;
	    constraints.anchor = GridBagConstraints.FIRST_LINE_START;
	    constraints.gridwidth = 2;
	    purgeIssues = new JCheckBox("Purge web application Burp issues before import.");
	    purgeIssues.setFont(new Font(webappid_label.getFont().getFamily(), 1, 12));
	    purgeIssues.setToolTipText(PURGE_BURP_ISSUES_TOOLTIP_TEXT);
	    exportBurpFilePanel.add(purgeIssues, constraints);  
	    
	    constraints.gridy = 6;
	    closeIssues = new JCheckBox("Close existing issues not reported anymore.");
	    closeIssues.setToolTipText(CLOSE_EXISTING_ISSUES_TOOLTIP_TEXT);
	    closeIssues.setFont(new Font(webappid_label.getFont().getFamily(), 1, 12));
	    exportBurpFilePanel.add(closeIssues, constraints);
	        
	    TitledBorder border = new TitledBorder("Qualys Import Settings");
	    border.setTitleJustification(TitledBorder.LEFT);
	    border.setTitlePosition(TitledBorder.TOP);
	    exportBurpFilePanel.setBorder(border);
	    
	    constraints.gridx = 0;
	    constraints.gridy = 7;
	    URL urlGif= this.getClass().getClassLoader().getResource("resources/spinner.gif");
  		ImageIcon imgiconGif = new ImageIcon(urlGif);
  		Image imgGif = imgiconGif.getImage() ;  
  		 
  		imgiconGif = new ImageIcon( imgGif );	
  		processing = new JLabel("Processing...", imgiconGif, JLabel.CENTER);
  		processing.setVisible(false);
  		exportBurpFilePanel.add(processing, constraints);
	    
	    buttonsPanel = new JPanel();
	   
	    constraints.anchor = GridBagConstraints.PAGE_END; //bottom of space
	    constraints.gridwidth = 2;   //2 columns wide
	    buttonsPanel.add(sendButton);
	    
	    JButton closeButton = new JButton("Close");
	    closeButton.setFont(new Font(webappid_label.getFont().getFamily(), 1, 10));
	    closeButton.addActionListener(new ActionListener() {
	        public void actionPerformed(ActionEvent e)
	        {
	           frame.dispose();
	        }
	    });
	    
	    constraints.anchor = GridBagConstraints.WEST;
	    buttonsPanel.add(closeButton);
	    
	    constraints.gridx = 0;
	    constraints.gridy = 8;
	    exportStatusLabel.setVisible(false);
	    exportBurpFilePanel.add(exportStatusLabel, constraints);
	    
	    constraints.gridx = 0;
	    constraints.gridy = 9;
	    failedExportStatusLabel.setVisible(false);
	    exportBurpFilePanel.add(failedExportStatusLabel, constraints);
	 
	    
	    exportBurpFilePanel.repaint();
	    
	    constraints.gridx = 0;
	    constraints.gridy = 0;
	    constraints.weightx = 1;
	    constraints.anchor = GridBagConstraints.NORTH;
	    frame.getContentPane().add(exportBurpFilePanel, constraints);
	    
	    constraints.gridy = 1;
	    constraints.anchor = GridBagConstraints.SOUTH;
	    frame.getContentPane().add(buttonsPanel, constraints);
	    frame.pack();
	    frame.setLocationRelativeTo(upperPanel);
	    frame.setVisible(true);
	  
  }
  
  
  private void refreshWebAppsList() {
	  if (wasSearchRequest == null ) {
		  logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : Cannot initiate the request... Please Validate the credentials again. \n");
	      logTextArea.setText(logBuilder.toString());
		  return;
	  }
	  
	  logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : Refreshing WebApps list for given platform... \n");
      logTextArea.setText(logBuilder.toString());
     
	  SwingWorker<String, Integer> worker = new SwingWorker<String, Integer>() {
		   @Override
		   protected String doInBackground() throws Exception {
			    exportStatusLabel.setVisible(false);
			    failedExportStatusLabel.setVisible(false);
 			    processing.setVisible(true);
		        return wasSearchRequest.getWebApplicationList();
		   }

		   // Can safely update the GUI from this method.
		   protected void done() {
		    
		    String response;
		    try {
		     // Retrieve the return value of doInBackground.
		     response = get();
		     if (wasSearchRequest.checkAuthenticationStatus(response)) {
		          webappLists = wasSearchRequest.parseWebApplications(response);     
		     }
		     processing.setVisible(false);
		     if (webappLists.isEmpty()) {
		    	  return;
		      }
		      paintNextPageInWizard(webappLists);
		      WebAppItem webAppItem = webappLists.get(0);  // by default first item selected after refresh
		      webAppURLLabel.setText("Web App URL : " + webAppItem.getWebAppItem_URL());
		      
		    } catch (InterruptedException e) {
		    	 logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : Error occurred refreshing webapps; " + e.getMessage() + "\n");
				 logTextArea.setText(logBuilder.toString());
		    } catch (ExecutionException e) {
		    	 logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : Error occurred refreshing webapps; " + e.getMessage() + "\n");
				 logTextArea.setText(logBuilder.toString());
		    }
		   }

		   @Override
		   // Can safely update the GUI from this method.
		   protected void process(List<Integer> chunks) {
		   
		   }		   
		  };
		  
		  worker.execute();
	  
  }

  public void paintNextPageInWizard(ArrayList<WebAppItem> webappLists)
  {
	  if (webappLists == null) {
		  return;
	  }
    frame.getContentPane().removeAll();
    
    buildConfigPanel();
    webapplistsLabel.clear();
    for (int counter = 0; counter < webappLists.size(); counter++) {
      WebAppItem webappItem = (WebAppItem)webappLists.get(counter);
      String webappName = webappItem.getWebAppItem_Name();
      webapplistsLabel.add(webappName);
    }
    
    DefaultComboBoxModel<String> webList_model = new DefaultComboBoxModel<String>(webapplistsLabel.toArray(new String[0]));
    webapplication_list_combox.setModel(webList_model);
    
    webapplication_list_combox.addActionListener(new ActionListener() {
	
	@Override
	public void actionPerformed(ActionEvent e) {
		if (webapplication_list_combox.getSelectedIndex() != -1) {
			 WebAppItem webAppItem = webappLists.get(webapplication_list_combox.getSelectedIndex());
			 webAppURLLabel.setText("Web App URL : " + webAppItem.getWebAppItem_URL());
		}
	}
	});
    
    WebAppItem webAppItem = webappLists.get(webapplication_list_combox.getSelectedIndex());
    webAppURLLabel.setText("Web App URL : " + webAppItem.getWebAppItem_URL()); 
    
    frame.getContentPane().add(exportBurpFilePanel);
    frame.getContentPane().repaint();
  }

  private String parseIHTTPService(IScanIssue issue)
  {
    IHttpService ihttpService = issue.getHttpService();
    String http_protocol = ihttpService.getProtocol();
    String http_host = ihttpService.getHost();
    String http_site_map_root = "";
    int http_port = ihttpService.getPort();
    if ((http_port == 80) || (http_port == 443)) {
      http_site_map_root = http_protocol + "://" + http_host + "/";
    } else
      http_site_map_root = http_protocol + "://" + http_host + ":" + http_port + "/";
    return http_site_map_root;
  }
  
  public class ExportFileButtonActionListener implements ActionListener
  {
    public ExportFileButtonActionListener() {}
  
    public void actionPerformed(ActionEvent e)
    {
       	
     	SwingWorker<String, Integer> worker = new SwingWorker<String, Integer>() {
    		WASImport wasImportRequest;
    		   @Override
    		   protected String doInBackground() throws Exception {
    		    
    		     if (scanIssues == null || webappLists == null) {
    		    	  return "";
    		      }
    		      
    		      int index = webapplication_list_combox.getSelectedIndex();
    		      WebAppItem selectedWebAppItem = (WebAppItem)webappLists.get(index);
    		      
    		      IScanIssue issue = scanIssues[0];
    		      String siteURL = parseIHTTPService(issue);
    		      
    		      if (!(selectedWebAppItem.getWebAppItem_URL().trim().contains(siteURL.trim()) || siteURL.trim().contains(selectedWebAppItem.getWebAppItem_URL().trim()))) {
    		    	  int dialogResult = JOptionPane.showConfirmDialog (frame, "WebApp URL does not match the site of which you want to import issues.\n Do you still want to proceed?", 
    		    			  "Confirm", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
    		    	  
    		    	  if(dialogResult != JOptionPane.YES_OPTION){
    		    		  return "";
    		    	  }
    		      }
    		      exportStatusLabel.setVisible(false);
    		      failedExportStatusLabel.setVisible(false);
    		      processing.setVisible(true);
    			  String webappID = selectedWebAppItem.getWebAppItem_ID();
    		      long webapp_id = Long.parseLong(webappID);
    		    
    		      if(QUALYS_Portal_ImportBurp_URL[portalSelectedIndex].equals(PCP)) {
    		    	  importBurpURL = processPlatformURL(qualysPlatformURL) + importApiPath;
    		      }else {
    		    	  importBurpURL = BurpExtender.QUALYS_Portal_ImportBurp_URL[portalSelectedIndex];
    		      }
				
				
				long unixTime = System.currentTimeMillis() / 1000L;
				String fileName = "burpextension_" + unixTime;
				   
				    File scanreportXMLTempFile = null;
					try {
					scanreportXMLTempFile = File.createTempFile(fileName, ".xml");
					scanreportXMLTempFile.deleteOnExit();
					logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : Making import API call in Qualys WAS \n");
					logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : Temp file On Default Location: " + scanreportXMLTempFile.getAbsolutePath() + "\n");
					logTextArea.setText(logBuilder.toString());
				} catch (IOException e1) {
					logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : Error creating temporary file of XML data while exporting\n");
					logTextArea.setText(logBuilder.toString());
				}
					
				try {
				  if (scanreportXMLTempFile.exists()) {
				    callbacks.generateScanReport("xml", scanIssues, scanreportXMLTempFile);
				     				    
				    wasImportRequest = new WASImport(scanreportXMLTempFile, webapp_id, username_login, String.valueOf(password_login), callbacks, importBurpURL, purgeIssues.isSelected(), closeIssues.isSelected());
				    
				    return wasImportRequest.sendXMLtoPortal();
				  }
    			}
    			catch (Exception ioe) {
    				logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : Failed exporting data to qualys; exception = " + ioe.getMessage() + "\n");
    				logTextArea.setText(logBuilder.toString());
    			}     
    	    	
    		    return "";
    		   }

    		   // Can safely update the GUI from this method.
    		   protected void done() {
    		    
    		    String response;
    		    try {
    		     // Retrieve the return value of doInBackground.
    		    	response = get();
    		    	
    		    	logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : Import API Response = " + response + "\n");
    				logTextArea.setText(logBuilder.toString());
    		    	
    		    	 if (wasImportRequest.checkExportStatus(response)) {
    		    		 processing.setVisible(false);
    		    		 
    		    		  int success = wasImportRequest.parseSuccessImports(response);
    		    		  int failed = wasImportRequest.parseFailedImports(response);
    				      String successMsg = "";
    				      String failMsg = "";
    				      if (success > 0) {
    				    	  successMsg = "Successful import of "+ success + " issue(s) into Qualys WAS. ";
    				    	  logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : " + successMsg + "\n");
        					  logTextArea.setText(logBuilder.toString());
    				      }
    				     
    				      if (failed > 0) {
    				    	  failMsg = "Failed to import " + failed + " issue(s). Please check Logs on Qualys WAS tab for details.";
    				    	  logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : Failed to import " + failed + " issue(s) into Qualys WAS. Please Check <errorRecords> element in the import API call response \n");
        					  logTextArea.setText(logBuilder.toString());
    				      }
    				     
    				      exportStatusLabel.setText(successMsg);
    				      exportStatusLabel.setForeground(Color.BLUE);
    				      exportStatusLabel.setFont(new Font("Courier New", 1, 12));
    				      exportStatusLabel.setVisible(true);
    				      
    				      failedExportStatusLabel.setText(failMsg);
    				      failedExportStatusLabel.setForeground(Color.RED);
    				      failedExportStatusLabel.setFont(new Font("Courier New", 1, 12));
    				      failedExportStatusLabel.setVisible(true);
    				      
    				    } else {
    				    	processing.setVisible(false);
    				    	logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : " + response + "\n");
    						logTextArea.setText(logBuilder.toString());
    						exportStatusLabel.setText(Export_XML_File_Fail_Error_Message);
    						exportStatusLabel.setForeground(Color.red);
    						exportStatusLabel.setFont(new Font("Courier New", 1, 12));
    						exportStatusLabel.setVisible(true);
    				    }
    		    	
    		    	
    		    } catch (InterruptedException e) {
    		    	logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : Failed exporting data to qualys; exception = " + e.getMessage() + "\n");
    				logTextArea.setText(logBuilder.toString());
    		    } catch (ExecutionException e) {
    		    	logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : Failed exporting data to qualys; exception = " + e.getMessage() + "\n");
    				logTextArea.setText(logBuilder.toString());
    		    }
    		   }
    		  };
    		  
    		  worker.execute();
    }
  }
  
  private String processPlatformURL(String qualysPlatformURL) {
	   String apiURL = qualysPlatformURL;
	  try {
		  if (qualysPlatformURL != null ) {
				if (qualysPlatformURL.endsWith("/")) {
					apiURL = qualysPlatformURL.substring(0, qualysPlatformURL.length()-1);
				}
				return apiURL.replaceFirst("//qualysguard.", "//qualysapi.");
			}
	  }catch (Exception e) {
		  logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " Exception processing qualys platform URL to API server; Exception: " +  "\n");
 		  logTextArea.setText(logBuilder.toString());
	  }
	return apiURL;
  }
  
  public class ValidateCredsActionListener implements ActionListener
  {
	private boolean isCredsValidationThroughWizard;
    public ValidateCredsActionListener(boolean isCredsValidationThroughWizard) {
    	this.isCredsValidationThroughWizard = isCredsValidationThroughWizard;
    }
	@Override
    public void actionPerformed(ActionEvent arg0)
    {
		
		SwingWorker<String, Integer> worker = new SwingWorker<String, Integer>() {
			   @Override
			   protected String doInBackground() throws Exception {
				    JTextField user;
				    JPasswordField pass;
				    JComboBox<String> qualys_URI;
				    
				 	       				    
					if (isCredsValidationThroughWizard) {
						user = username_field;
						pass = password_field;
						qualys_URI = qualysPortal_URI_list;
						
					} else {
						user = username_field_tab;
						pass = password_field_tab;
						qualys_URI = qualysPortal_URI_list_tab;
						
					}	
					
				  authenticationLabel.setVisible(false);
				  authenticationLabelInTab.setVisible(false);
			      if ((user.getText() == null) || (user.getText().trim().isEmpty()) || (user.getText().trim().equals(""))) {
			        JOptionPane.showMessageDialog(upperPanel, Empty_Login_UserName_InputField_Error_Message, "Error Message", 0);
			      }
			      else if ((pass.getPassword() == null) || (pass.getPassword().length == 0)) {
			        JOptionPane.showMessageDialog(upperPanel, Empty_Login_Password_InputField_Error_Message, "Error Message", 0);
			      } else {
			    	  if (isCredsValidationThroughWizard) {
			    		  processing.setVisible(true);
			    	  } else {
			    		  processingInTab.setVisible(true);
			    	  }    	
			        username_login = user.getText().trim();
			        password_login = pass.getPassword();
			        portalSelectedIndex = qualys_URI.getSelectedIndex();
			        
			        if (qualys_URI.getSelectedIndex() != -1) {
						String url = QUALYS_Portal_Name_List[qualys_URI.getSelectedIndex()];
						if (url.equals(PCP)) {
							if (isCredsValidationThroughWizard) {
								qualysPlatformURL = pcpURL.getText().trim();
							}else {
								qualysPlatformURL = pcpURLInTab.getText().trim();
							}
							if(qualysPlatformURL == null || (qualysPlatformURL.trim().isEmpty()) ){
								JOptionPane.showMessageDialog(upperPanel, Empty_Platform_URL_InputField_Error_Message, "Error Message", 0);
								return "";
							}
							searchWebappsURL = processPlatformURL(qualysPlatformURL) + searchApiPath;
						} else {
							searchWebappsURL = QUALYS_Portal_Webapp_List[qualys_URI.getSelectedIndex()];
						}
					}
			        
			        
			        wasSearchRequest = new WASSearch(searchWebappsURL, username_login, String.valueOf(password_login), callbacks);
			        return wasSearchRequest.getWebApplicationList();
			   }
			      return "";
			  }

			// Can safely update the GUI from this method.
			   protected void done() {
			    
			    String response;
			    try {
			     // Retrieve the return value of doInBackground.
			     response = get();
			     if (wasSearchRequest.checkAuthenticationStatus(response)) {
			          webappLists = wasSearchRequest.parseWebApplications(response);  
			          logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : " + Login_Successful_Message +  "\n");
		      		  logTextArea.setText(logBuilder.toString());
		      		  
		      		  if (isCredsValidationThroughWizard) {
		      			  processing.setVisible(false);
			              paintNextPageInWizard(webappLists);
			              //fill in the username and password in tab menu automatically
			              username_field_tab.setText(username_login); 		
			              password_field_tab.setText(String.valueOf(password_login));
			              if (qualysPlatformURL != null) {
			            	  pcpURLInTab.setText(qualysPlatformURL);
			            	  pcpURLInTab.setVisible(true);
			            	  pcpURLLabelInTab.setVisible(true);
			              } 
			              qualysPortal_URI_list_tab.setSelectedIndex(portalSelectedIndex);
			              
			          } else {
			        	  processingInTab.setVisible(false);
			        	  authenticationLabelInTab.setText(Login_Successful_Message);
			              authenticationLabelInTab.setVisible(true);
			              authenticationLabelInTab.setFont(new Font("Courier New", 1, 12));
			              authenticationLabelInTab.setForeground(Color.blue);
			          }   
			        } else {
			    	  username_login = null;
			          password_login = null;
			          logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : " + Authentication_Fail_Error_Message + "\n");
		      		  logTextArea.setText(logBuilder.toString());
		      		  
			          if (isCredsValidationThroughWizard) {
			        	  processing.setVisible(false);
			        	  authenticationLabel.setText(Authentication_Fail_Error_Message);
			              authenticationLabel.setVisible(true);
			              authenticationLabel.setFont(new Font("Courier New", 1, 12));
			              authenticationLabel.setForeground(Color.red);
			          } else {
			        	  processingInTab.setVisible(false);
			        	  authenticationLabelInTab.setText(Authentication_Fail_Error_Message);
			              authenticationLabelInTab.setVisible(true);
			              authenticationLabelInTab.setFont(new Font("Courier New", 1, 12));
			              authenticationLabelInTab.setForeground(Color.red);
			        	 
			          }         
			        }
			        
			        logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " :  Response data: \n" + response + "\n");
					logTextArea.setText(logBuilder.toString());
			    } catch (InterruptedException e) {
			    	 logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : Error occurred fetching webapps; " + e.getMessage() + "\n");
					 logTextArea.setText(logBuilder.toString());
			    } catch (ExecutionException e) {
			    	 logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : Error occurred fetching webapps; " + e.getMessage() + "\n");
					 logTextArea.setText(logBuilder.toString());
			    }
			   }   
			   
			  };
			  
			  worker.execute();
    }
  }
  
@Override
public void extensionUnloaded() {
	// TODO Auto-generated method stub
	
}
}
