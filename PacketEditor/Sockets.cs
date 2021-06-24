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
        Glob.PipeHeader strPipeMsgOut = new Glob.PipeHeader();
        readonly NamedPipeClientStream pipeOut;

        public Sockets(DataTable dtSockets, SocketInfo sInfo, NamedPipeClientStream pOut)
        {
            InitializeComponent();
            
            pipeOut = pOut;

            foreach (DataRow row in dtSockets.Rows)
            {
                int i = dgridSockets.Rows.Add();
                dgridSockets.Rows[i].Cells["socket"].Value = ((int)row["socket"]).ToString("X4");

                if (row["proto"].ToString() != string.Empty)
                    dgridSockets.Rows[i].Cells["proto"].Value = sInfo.Proto((int)row["proto"]);

                if (row["fam"].ToString() != string.Empty
                    && ((int)row["fam"] >= 0) && ((int)row["fam"] <= sInfo.afamily.Length - 1))
                        dgridSockets.Rows[i].Cells["fam"].Value = sInfo.afamily[(int)row["fam"]];

                if (row["type"].ToString() != string.Empty
                    && ((int)row["type"] >= 0) && ((int)row["type"] <= sInfo.atype.Length - 1))
                        dgridSockets.Rows[i].Cells["type"].Value = sInfo.atype[(int)row["type"]];

                if (row["lastapi"].ToString() != string.Empty)
                    dgridSockets.Rows[i].Cells["lastapi"].Value = sInfo.Api((int)row["lastapi"]);

                if (row["lastmsg"].ToString() != string.Empty)
                    dgridSockets.Rows[i].Cells["lastmsg"].Value = sInfo.Msg((int) row["lastmsg"]);

                dgridSockets.Rows[i].Cells["local"].Value = row["local"].ToString();
                dgridSockets.Rows[i].Cells["remote"].Value = row["remote"].ToString();
            }
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
                strPipeMsgOut.command = Glob.CMD_INJECT;
                strPipeMsgOut.sockid = int.Parse(dgridSockets.SelectedRows[0].Cells["socket"].Value.ToString(), System.Globalization.NumberStyles.AllowHexSpecifier);
                strPipeMsgOut.function = Glob.FUNC_SHUTDOWN;
                strPipeMsgOut.extra = (int)SocketShutdown.Receive;
                strPipeMsgOut.datasize = 0;
                pipeOut.Write(Glob.RawSerializeEx(strPipeMsgOut), 0, Marshal.SizeOf(strPipeMsgOut));
            }
        }

        private void sDSENDToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (dgridSockets.SelectedRows.Count != 0)
            {
                strPipeMsgOut.command = Glob.CMD_INJECT;
                strPipeMsgOut.sockid = int.Parse(dgridSockets.SelectedRows[0].Cells["socket"].Value.ToString(), System.Globalization.NumberStyles.AllowHexSpecifier);
                strPipeMsgOut.function = Glob.FUNC_SHUTDOWN;
                strPipeMsgOut.extra = (int)SocketShutdown.Send;
                strPipeMsgOut.datasize = 0;
                pipeOut.Write(Glob.RawSerializeEx(strPipeMsgOut), 0, Marshal.SizeOf(strPipeMsgOut));
            }
        }

        private void sDBOTHToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (dgridSockets.SelectedRows.Count != 0)
            {
                strPipeMsgOut.command = Glob.CMD_INJECT;
                strPipeMsgOut.sockid = int.Parse(dgridSockets.SelectedRows[0].Cells["socket"].Value.ToString(), System.Globalization.NumberStyles.AllowHexSpecifier);
                strPipeMsgOut.function = Glob.FUNC_SHUTDOWN;
                strPipeMsgOut.extra = (int)SocketShutdown.Both;
                strPipeMsgOut.datasize = 0;
                pipeOut.Write(Glob.RawSerializeEx(strPipeMsgOut), 0, Marshal.SizeOf(strPipeMsgOut));

            }
        }

        private void closeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (dgridSockets.SelectedRows.Count != 0)
            {
                strPipeMsgOut.command = Glob.CMD_INJECT;
                strPipeMsgOut.sockid = int.Parse(dgridSockets.SelectedRows[0].Cells["socket"].Value.ToString(), System.Globalization.NumberStyles.AllowHexSpecifier);
                strPipeMsgOut.function = Glob.FUNC_CLOSESOCKET;
                strPipeMsgOut.datasize = 0;
                pipeOut.Write(Glob.RawSerializeEx(strPipeMsgOut), 0, Marshal.SizeOf(strPipeMsgOut));
            }
        }

        private void replayEditorToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (dgridSockets.SelectedRows.Count != 0)
            {
                var frmChReplay = new ReplayEditor(new byte[0], int.Parse(dgridSockets.SelectedRows[0].Cells["socket"].Value.ToString(), System.Globalization.NumberStyles.AllowHexSpecifier), pipeOut);
                if (this.TopMost)
                    frmChReplay.TopMost = true;
                frmChReplay.Show();
            }
        }

        private void dgridSockets_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (e.KeyChar == 27)
            {
                this.Close();
            }
        }
    }
}
