using System;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.IO.Pipes;
using Be.Windows.Forms;

namespace PacketEditor
{
    public partial class ReplayEditor : Form
    {
        private readonly NamedPipeClientStream pipeOut;

        public ReplayEditor(byte[] replayData, int socket, NamedPipeClientStream pipe)
        {
            InitializeComponent();

            hexBox1.ByteProvider = new DynamicByteProvider(replayData);
            pipeOut = pipe;
            txtSockID.Text = socket.ToString("X4");
        }

        void CloseForm()
        {
            Close();
        }

        private void btnCancel_Click(object sender, EventArgs e)
        {
            CloseForm();
        }

        private void btnSend_Click(object sender, EventArgs e)
        {
            Glob.PipeHeader strPipeMsgOut = new Glob.PipeHeader();
            try
            {
                strPipeMsgOut.sockid = int.Parse(txtSockID.Text, System.Globalization.NumberStyles.HexNumber);
            }
            catch
            {
                MessageBox.Show("Invalid socket ID.", "Error!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                txtSockID.SelectAll();
                txtSockID.Focus();
                return;
            }

            DynamicByteProvider bytePro = hexBox1.ByteProvider as DynamicByteProvider;
            ByteCollection bcBytes = bytePro.Bytes;
            strPipeMsgOut.command = Glob.CMD.Inject;
            strPipeMsgOut.function = Glob.FUNC_SEND;
            strPipeMsgOut.datasize = bcBytes.Count;

            byte[] buf = Glob.RawSerializeEx(strPipeMsgOut);
            int size = Marshal.SizeOf(strPipeMsgOut);
            for (int times = int.Parse(txtTimes.Text); times > 0; times--)
            {
                pipeOut.Write(buf, 0, size);
                pipeOut.Write(bcBytes.GetBytes(), 0, strPipeMsgOut.datasize);
            }
        }

        private void frmReplayEditor_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (e.KeyChar == (char)Keys.Escape)
            {
                CloseForm();
            }
        }

        private void hexBox1_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (e.KeyChar == (char)Keys.Escape)
            {
                CloseForm();
            }
        }

        private void frmReplayEditor_Activated(object sender, EventArgs e)
        {
            if (this.TopMost)
            {
                this.Opacity = 1;
            }
        }

        private void frmReplayEditor_Deactivate(object sender, EventArgs e)
        {
            if (this.TopMost)
            {
                this.Opacity = .5;
            }
        }
    }
}
