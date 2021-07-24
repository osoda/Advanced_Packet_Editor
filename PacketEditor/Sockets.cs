using System;
using System.Data;
using System.Windows.Forms;
using System.Net.Sockets;
using System.IO.Pipes;
using System.Runtime.InteropServices;

namespace PacketEditor
{
    public partial class Sockets : Form
    {
        private readonly NamedPipeClientStream pipeOut;

        public Sockets(DataTable dtSockets, NamedPipeClientStream pOut)
        {
            InitializeComponent();

            pipeOut = pOut;

            foreach (DataRow row in dtSockets.Rows)
            {
                int i = dgridSockets.Rows.Add();
                dgridSockets.Rows[i].Cells["socket"].Value = ((int)row["socket"]).ToString("X4");

                if (row["proto"].ToString() != string.Empty)
                    dgridSockets.Rows[i].Cells["proto"].Value = SocketInfoUtils.ProtocolName((int)row["proto"]);

                if (row["fam"].ToString() != string.Empty)
                    dgridSockets.Rows[i].Cells["fam"].Value = SocketInfoUtils.AddressFamilyName((int)row["fam"]);

                if (row["type"].ToString() != string.Empty)
                    dgridSockets.Rows[i].Cells["type"].Value = SocketInfoUtils.SocketTypeName((int)row["type"]);

                if (row["lastapi"].ToString() != string.Empty)
                    dgridSockets.Rows[i].Cells["lastapi"].Value = SocketInfoUtils.Api((int)row["lastapi"]);

                if (row["lastmsg"].ToString() != string.Empty)
                    dgridSockets.Rows[i].Cells["lastmsg"].Value = SocketInfoUtils.Msg((int)row["lastmsg"]);

                dgridSockets.Rows[i].Cells["local"].Value = row["local"].ToString();
                dgridSockets.Rows[i].Cells["remote"].Value = row["remote"].ToString();
            }
        }

        private void CloseForm()
        {
            Close();
        }

        private void frmSockets_Activated(object sender, EventArgs e)
        {
            if (this.TopMost)
            {
                this.Opacity = 1;
            }
        }

        private void frmSockets_Deactivate(object sender, EventArgs e)
        {
            if (this.TopMost)
            {
                this.Opacity = .5;
            }
        }

        private void sDRECVToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (dgridSockets.SelectedRows.Count != 0)
            {
                PipeHeader strPipeMsgOut = new PipeHeader
                {
                    command = CMD.Inject,
                    sockid = int.Parse(dgridSockets.SelectedRows[0].Cells["socket"].Value.ToString(), System.Globalization.NumberStyles.AllowHexSpecifier),
                    function = Glob.FUNC_SHUTDOWN,
                    extra = (int)SocketShutdown.Receive,
                    datasize = 0
                };
                pipeOut.Write(Glob.RawSerializeEx(strPipeMsgOut), 0, Marshal.SizeOf(strPipeMsgOut));
            }
        }

        private void sDSENDToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (dgridSockets.SelectedRows.Count != 0)
            {
                PipeHeader strPipeMsgOut = new PipeHeader
                {
                    command = CMD.Inject,
                    sockid = int.Parse(dgridSockets.SelectedRows[0].Cells["socket"].Value.ToString(), System.Globalization.NumberStyles.AllowHexSpecifier),
                    function = Glob.FUNC_SHUTDOWN,
                    extra = (int)SocketShutdown.Send,
                    datasize = 0
                };
                pipeOut.Write(Glob.RawSerializeEx(strPipeMsgOut), 0, Marshal.SizeOf(strPipeMsgOut));
            }
        }

        private void sDBOTHToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (dgridSockets.SelectedRows.Count != 0)
            {
                PipeHeader strPipeMsgOut = new PipeHeader
                {
                    command = CMD.Inject,
                    sockid = int.Parse(dgridSockets.SelectedRows[0].Cells["socket"].Value.ToString(), System.Globalization.NumberStyles.AllowHexSpecifier),
                    function = Glob.FUNC_SHUTDOWN,
                    extra = (int)SocketShutdown.Both,
                    datasize = 0
                };
                pipeOut.Write(Glob.RawSerializeEx(strPipeMsgOut), 0, Marshal.SizeOf(strPipeMsgOut));
            }
        }

        private void closeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (dgridSockets.SelectedRows.Count != 0)
            {
                PipeHeader strPipeMsgOut = new PipeHeader
                {
                    command = CMD.Inject,
                    sockid = int.Parse(dgridSockets.SelectedRows[0].Cells["socket"].Value.ToString(), System.Globalization.NumberStyles.AllowHexSpecifier),
                    function = Glob.FUNC_CLOSESOCKET,
                    datasize = 0
                };
                pipeOut.Write(Glob.RawSerializeEx(strPipeMsgOut), 0, Marshal.SizeOf(strPipeMsgOut));
            }
        }

        private void replayEditorToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (dgridSockets.SelectedRows.Count != 0)
            {
                var frmChReplay = new ReplayEditor(new byte[0],
                    int.Parse(dgridSockets.SelectedRows[0].Cells["socket"].Value.ToString(), System.Globalization.NumberStyles.AllowHexSpecifier),
                    pipeOut);
                if (this.TopMost)
                    frmChReplay.TopMost = true;
                frmChReplay.Show();
            }
        }

        private void dgridSockets_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (e.KeyChar == (char)Keys.Escape)
            {
                CloseForm();
            }
        }
    }
}
