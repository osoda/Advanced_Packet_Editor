using System;
using System.Data;
using System.Text;
using System.Windows.Forms;

namespace PacketEditor
{
    public partial class Filters : Form
    {
        readonly DataTable dtFilters;
        readonly SocketInfo sInfo;

        public Filters(DataTable dt, SocketInfo si)
        {
            InitializeComponent();

            dtFilters = dt;
            sInfo = si;

            StringBuilder funs = new StringBuilder();
            foreach (DataRow dr in dt.Rows)
            {
                int i = dgridFilters.Rows.Add();
                funs.Clear();
                dgridFilters.Rows[i].Cells["name"].Value = dr["id"].ToString();
                dgridFilters.Rows[i].Cells["enabled"].Value = dr["enabled"];

                foreach (byte f in (byte[])dr["MsgFunction"])
                {
                    funs.Append(si.Msg(f) + " ");
                }
                foreach (byte f in (byte[])dr["APIFunction"])
                {
                    funs.Append(si.Api(f) + " ");
                }
                foreach (byte f in (byte[])dr["DNSFunction"])
                {
                    funs.Append(si.Api(f) + " ");
                }

                if (funs.ToString() != string.Empty)
                {
                    dgridFilters.Rows[i].Cells["function"].Value = funs.ToString().TrimEnd();
                }
            }
        }

        private void frmFilters_Activated(object sender, EventArgs e)
        {
            if (this.TopMost)
            {
                this.Opacity = 1;
            }
        }

        private void frmFilters_Deactivate(object sender, EventArgs e)
        {
            if (this.TopMost)
            {
                this.Opacity = .5;
            }
        }

        private void dgridFilters_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (e.KeyChar == 27)
            {
                this.Close();
            }
            else if (e.KeyChar == 32)
            {
                if ((bool)dgridFilters.SelectedRows[0].Cells["enabled"].Value == false)
                {
                    dgridFilters.SelectedRows[0].Cells["enabled"].Value = true;
                    dtFilters.Rows.Find(dgridFilters.SelectedRows[0].Cells["name"].Value)["enabled"] = true;
                }
                else
                {
                    dgridFilters.SelectedRows[0].Cells["enabled"].Value = false;
                    dtFilters.Rows.Find(dgridFilters.SelectedRows[0].Cells["name"].Value)["enabled"] = false;
                }
            }
        }

        private void btnDel_Click(object sender, EventArgs e)
        {
            foreach (DataGridViewRow srow in dgridFilters.SelectedRows)
            {
                DataRow drsock = dtFilters.Rows.Find(srow.Cells["name"].Value);
                if (drsock != null)
                {
                    drsock.Delete();
                }
                dgridFilters.Rows.Remove(srow);
            }
        }

        private void btnAdd_Click(object sender, EventArgs e)
        {
            DataRow dr = dtFilters.NewRow();
            EditFilter frmChReplay = new EditFilter(dr, sInfo, dtFilters, dgridFilters, 0);
            if (this.TopMost)
                frmChReplay.TopMost = true;
            frmChReplay.Show();
        }

        private void btnClose_Click(object sender, EventArgs e)
        {
            this.Close();
        }

        private void dgridFilters_CellDoubleClick(object sender, DataGridViewCellEventArgs e)
        {
            if ((e.ColumnIndex != 0) && (e.RowIndex != -1))
            {
                DataRow dr = dtFilters.Rows[e.RowIndex];
                EditFilter frmChReplay = new EditFilter(dr, sInfo, dtFilters, dgridFilters, e.RowIndex);
                if (this.TopMost)
                    frmChReplay.TopMost = true;
                frmChReplay.Show();
            }
        }

        private void dgridFilters_CellMouseClick(object sender, DataGridViewCellMouseEventArgs e)
        {
            if ((e.ColumnIndex == 0) && (e.RowIndex != -1))
            {
                if (dgridFilters[e.ColumnIndex, e.RowIndex].GetContentBounds(e.RowIndex).Contains(e.Location))
                {
                    if ((bool)dgridFilters.Rows[e.RowIndex].Cells[e.ColumnIndex].Value == false)
                    {
                        dgridFilters.Rows[e.RowIndex].Cells[e.ColumnIndex].Value = true;
                        dtFilters.Rows.Find(dgridFilters.Rows[e.RowIndex].Cells["name"].Value)["enabled"] = true;
                    }
                    else
                    {
                        dgridFilters.Rows[e.RowIndex].Cells[e.ColumnIndex].Value = false;
                        dtFilters.Rows.Find(dgridFilters.Rows[e.RowIndex].Cells["name"].Value)["enabled"] = false;
                    }
                }
            }
        }
    }
}
