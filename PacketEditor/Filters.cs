using System;
using System.Data;
using System.Text;
using System.Windows.Forms;

namespace PacketEditor
{
    public partial class Filters : Form
    {
        private readonly DataTable dtFilters;

        public Filters(DataTable dt)
        {
            InitializeComponent();

            dtFilters = dt;

            var funs = new StringBuilder();
            foreach (DataRow dr in dt.Rows)
            {
                funs.Clear();
                int idx = dgridFilters.Rows.Add();
                dgridFilters.Rows[idx].Cells["name"].Value = dr["id"].ToString();
                dgridFilters.Rows[idx].Cells["enabled"].Value = dr["enabled"];

                foreach (byte f in (byte[])dr["MsgFunction"])
                {
                    funs.Append(SocketInfoUtils.Msg(f) + " ");
                }
                foreach (byte f in (byte[])dr["APIFunction"])
                {
                    funs.Append(SocketInfoUtils.Api(f) + " ");
                }
                foreach (byte f in (byte[])dr["DNSFunction"])
                {
                    funs.Append(SocketInfoUtils.Api(f) + " ");
                }

                if (funs.Length != 0)
                {
                    dgridFilters.Rows[idx].Cells["function"].Value = funs.ToString().TrimEnd();
                }
            }
        }

        private void CloseForm()
        {
            Close();
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
            if (e.KeyChar == (char)Keys.Escape)
            {
                CloseForm();
            }
            else if (e.KeyChar == (char)Keys.Space)
            {
                if (!(bool)dgridFilters.SelectedRows[0].Cells["enabled"].Value)
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
                drsock?.Delete();

                dgridFilters.Rows.Remove(srow);
            }
        }

        private void btnAdd_Click(object sender, EventArgs e)
        {
            var frmChReplay = new EditFilter(dtFilters.NewRow(), dtFilters, dgridFilters, 0);
            if (this.TopMost)
                frmChReplay.TopMost = true;
            frmChReplay.Show();
        }

        private void btnClose_Click(object sender, EventArgs e)
        {
            CloseForm();
        }

        private void dgridFilters_CellDoubleClick(object sender, DataGridViewCellEventArgs e)
        {
            if ((e.ColumnIndex != 0) && (e.RowIndex != -1))
            {
                DataRow dr = dtFilters.Rows[e.RowIndex];
                var frmChReplay = new EditFilter(dr, dtFilters, dgridFilters, e.RowIndex);
                if (this.TopMost)
                    frmChReplay.TopMost = true;
                frmChReplay.Show();
            }
        }

        private void dgridFilters_CellMouseClick(object sender, DataGridViewCellMouseEventArgs e)
        {
            if ((e.ColumnIndex == 0) && (e.RowIndex != -1)
                && dgridFilters[e.ColumnIndex, e.RowIndex].GetContentBounds(e.RowIndex).Contains(e.Location))
            {
                if (!(bool)dgridFilters.Rows[e.RowIndex].Cells[e.ColumnIndex].Value)
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
