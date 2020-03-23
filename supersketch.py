from functools import reduce
import math


def egcd(a, b):
    # Extended Euclidean algorithm
    if 0 == b:
        return 1, 0, a
    x, y, q = egcd(b, a % b)
    x, y = y, (x - a // b * y)
    return x, y, q


def chinese_remainder(mod_list, remainder_list):
    # Chinese Remainder Theorem (CRT)
    mod_product = reduce(lambda x, y: x * y, mod_list)
    mi_list = [mod_product // x for x in mod_list]
    mi_inverse = [egcd(mi_list[i], mod_list[i])[0] for i in range(len(mi_list))]
    x = 0
    for i in range(len(remainder_list)):
        x += mi_list[i] * mi_inverse[i] * remainder_list[i]
        x %= mod_product
    return x


def addr2dec(addr):
    # Dotted decimal notation IP  to Decimal integer IP
    items = [int(x) for x in addr.split(".")]
    return sum([items[i] << [24, 16, 8, 0][i] for i in range(4)])


def dec2addr(dec):
    # Decimal integer IP TO Dotted decimal notation IP
    return ".".join([str(dec >> x & 0xff) for x in [24, 16, 8, 0]])


class SuperSketch:
    # operations and functions of supersketch

    def __init__(self, n, p, u):
        self.n = n
        self.p = p
        self.u = u
        self.dt = 0.003         # percentage thresholds for super spreader/receiver identification
        self.ct = 0.002         # percentage thresholds for super changer identification
        self.sketch = None
        self.Flag_row = None
        self.Flag_column = None
        self.row_change = None
        self.pre_row_dict = None
        self.sc_frequency = None

    def generate_ss(self):
        # sketch initialization
        self.sketch = []
        for i in range(self.n):
            a = {}
            self.sketch.append(a)

    def generate_flag(self):
        # Flag initialization
        self.Flag_row = []
        self.Flag_column = []
        for i in range(self.n - 1):
            a = {}
            b = {}
            self.Flag_row.append(a)
            self.Flag_column.append(b)

    def initialize(self):
        # initialize
        self.generate_ss()
        self.generate_flag()

    def update(self, source, destination, port):
        # update operation
        src = addr2dec(source)
        des = addr2dec(destination)

        for x in range(self.n):
            row = int(src % self.p[x])
            column1 = int(des % self.p[x])
            column2 = int(port % self.u[x])

            # sketch[x]   {row:{column1:{column2,...},...},...}
            if row in self.sketch[x]:
                if column1 in self.sketch[x][row]:
                    self.sketch[x][row][column1].add(column2)
                else:
                    self.sketch[x][row][column1] = {column2}
            else:
                self.sketch[x][row] = {column1: {column2}}
            # Flag_row[x]   {row:{row_next,...},...}
            # Flag_column[x]    {column1:{column1_next,...},...}
            if x != self.n-1:
                if row in self.Flag_row[x]:
                    self.Flag_row[x][row].add(int(src % self.p[x+1]))
                else:
                    self.Flag_row[x][row] = {int(src % self.p[x+1])}

                if column1 in self.Flag_column[x]:
                    self.Flag_column[x][column1].add(int(des % self.p[x + 1]))
                else:
                    self.Flag_column[x][column1] = {int(des % self.p[x + 1])}
            else:
                continue

    def process_data(self, table, low_rows, up_rows):
        # process flows
        for i in range(low_rows, up_rows):
            source = table.loc[i, 'Src IP']
            destination = table.loc[i, 'Dst IP']
            desport = table.loc[i, 'Dst Port']
            self.update(source, destination, desport)

    def cal_dci(self, i, row):
        # calculate the dc(destination cardinality) of the row in SSi
        if row not in self.sketch[i]:  # if the row doesn't exist in sketch, its dci is 0.
            dci = 0
        else:
            v = self.p[i] - len(self.sketch[i][row])
            if v == 0:
                v = 1
            dci = round((-self.p[i]) * math.log(v / self.p[i]), 2)
        return dci

    def cal_dpci(self, i, row):
        # calculate the dpc(destination port cardinality) of the row in SSi
        if row not in self.sketch[i]:  # if the row doesn't exist in sketch, its dpci is 0.
            dpci = 0
        else:
            dp_set = set()
            for column in self.sketch[i][row]:
                dp_set = dp_set | self.sketch[i][row][column]
            v = self.u[i] - len(dp_set)
            if v == 0:
                v = 1
            dpci = round((-self.u[i]) * math.log(v / self.u[i]), 2)
        return dpci

    def cal_sci(self, i, column):
        # calculate the sc(source cardinality) of the column in SSi
        freq = self.sc_frequency[i].get(column, 0)
        v = self.p[i] - freq
        if v == self.p[i]:  # if the column doesn't exist in sketch, its sci is 0.
            sci = 0
        else:
            if v == 0:
                v = 1
            sci = round((-self.p[i]) * math.log(v / self.p[i]), 2)
        return sci

    def cal_dc(self, source):
        # calculate the dc of source
        src = addr2dec(source)
        dc_list = []
        for i in range(self.n):
            row = src % self.p[i]
            dci = self.cal_dci(i, row)
            dc_list.append(dci)
        dc = int(min(dc_list))
        return dc

    def cal_dpc(self, source):
        # calculate the dpc of source
        src = addr2dec(source)
        dpc_list = []
        for i in range(self.n):
            row = src % self.p[i]
            dpci = self.cal_dpci(i, row)
            dpc_list.append(dpci)
        dpc = int(min(dpc_list))
        return dpc

    def cal_sc(self, destination):
        # calculate the sc of destination
        des = addr2dec(destination)
        sc_list = []
        for i in range(self.n):
            column = des % self.p[i]
            sci = self.cal_sci(i, column)
            sc_list.append(sci)
        sc = int(min(sc_list))
        return sc

    def recon_sip(self, abrow_list, cur=0, num_list=None, sip_list=None, rownum=None):
        # reversibly reconstruct abnormal source addresses
        if cur == 0:
            sip_list = []
            for num in abrow_list[0]:
                original_list = [num]
                for flag in self.Flag_row[cur][num]:
                    if flag in abrow_list[cur + 1]:
                        num_list = original_list.copy()
                        num_list.append(flag)
                        rownum = flag
                        self.recon_sip(abrow_list, cur + 1, num_list, sip_list, rownum)
                    else:
                        continue
            return sip_list
        elif cur == self.n - 1:
            ipaddress = dec2addr(chinese_remainder(self.p, num_list))
            sip_list.append(ipaddress)
        else:
            original_list = num_list.copy()
            for flag in self.Flag_row[cur][rownum]:
                if flag in abrow_list[cur + 1]:
                    num_list = original_list.copy()
                    num_list.append(flag)
                    rownum = flag
                    self.recon_sip(abrow_list, cur + 1, num_list, sip_list, rownum)
                else:
                    continue

    def recon_dip(self, abcol_list, cur=0, num_list=None, dip_list=None, colnum=None):
        # reversibly reconstruct abnormal destination addresses
        if cur == 0:
            dip_list = []
            for num in abcol_list[0]:
                original_list = [num]
                for flag in self.Flag_column[cur][num]:
                    if flag in abcol_list[cur + 1]:
                        num_list = original_list.copy()
                        num_list.append(flag)
                        colnum = flag
                        self.recon_dip(abcol_list, cur + 1, num_list, dip_list, colnum)
                    else:
                        continue
            return dip_list
        elif cur == self.n - 1:
            ipaddress = dec2addr(chinese_remainder(self.p, num_list))
            dip_list.append(ipaddress)
        else:
            original_list = num_list.copy()
            for flag in self.Flag_column[cur][colnum]:
                if flag in abcol_list[cur + 1]:
                    num_list = original_list.copy()
                    num_list.append(flag)
                    colnum = flag
                    self.recon_dip(abcol_list, cur + 1, num_list, dip_list, colnum)
                else:
                    continue

    def cal_abrow_list(self):
        # identify abnormal rows
        abrow_list_spreader = []
        abrow_list_changer = []
        new_row_dict = []
        if self.pre_row_dict is None:
            for i in range(self.n):
                abrow_spreader = []
                new_row_dict.append({})
                F1i = 0
                F2i = 0
                for row in self.sketch[i]:
                    dci_row = self.cal_dci(i, row)
                    dpci_row = self.cal_dpci(i, row)
                    new_row_dict[i][row] = [dci_row, dpci_row]
                    F1i += dci_row
                    F2i += dpci_row
                for row in new_row_dict[i]:
                    if new_row_dict[i][row][0] >= (self.dt * F1i) or new_row_dict[i][row][1] >= (self.dt * F2i):
                        abrow_spreader.append(row)
                abrow_list_spreader.append(abrow_spreader)
        else:
            self.row_change = []
            for i in range(self.n):
                abrow_spreader = []
                abrow_changer = []
                self.row_change.append({})
                new_row_dict.append({})
                C1i = 0
                C2i = 0
                F1i = 0
                F2i = 0
                for row in self.sketch[i]:
                    dci_row = self.cal_dci(i, row)
                    dpci_row = self.cal_dpci(i, row)
                    new_row_dict[i][row] = [dci_row, dpci_row]
                    F1i += dci_row
                    F2i += dpci_row
                    if row not in self.pre_row_dict[i]:
                        C1i += dci_row
                        C2i += dpci_row
                        self.row_change[i][row] = [dci_row, dpci_row]
                    else:
                        change_dci_row = max(0, dci_row - self.pre_row_dict[i][row][0])
                        change_dpci_row = max(0, dpci_row - self.pre_row_dict[i][row][1])
                        C1i += change_dci_row
                        C2i += change_dpci_row
                        self.row_change[i][row] = [change_dci_row, change_dpci_row]
                for row in new_row_dict[i]:
                    if new_row_dict[i][row][0] >= (self.dt * F1i) or new_row_dict[i][row][1] >= (self.dt * F2i):
                        abrow_spreader.append(row)
                    if self.row_change[i][row][0] >= (self.ct * C1i) or self.row_change[i][row][1] >= (self.ct * C2i):
                        abrow_changer.append(row)
                abrow_list_spreader.append(abrow_spreader)
                abrow_list_changer.append(abrow_changer)            
        self.pre_row_dict = new_row_dict
        return abrow_list_spreader, abrow_list_changer

    def cal_abcol_list(self):
        # identify abnormal columns
        abcol_list_receiver = []
        new_col_dict = []
        for i in range(self.n):
            col_set = set()
            abcol_receiver = []
            new_col_dict.append({})
            F3i = 0
            for row in self.sketch[i]:
                for col in self.sketch[i][row]:
                    col_set.add(col)
            for col in col_set:
                sci_col = self.cal_sci(i, col)
                new_col_dict[i][col] = sci_col
                F3i += sci_col
            for col in new_col_dict[i]:
                if new_col_dict[i][col] >= self.dt * F3i:
                    abcol_receiver.append(col)
            abcol_list_receiver.append(abcol_receiver)
        return abcol_list_receiver

    def dc_change(self, source):
        # calculate the sum of dci(source), i = 1,...,N
        src = addr2dec(source)
        dc_change = 0
        for i in range(self.n):
            row = src % self.p[i]
            if row in self.row_change[i]:
                dc_change += self.row_change[i][row][0]
            else:
                dc_change += 0
        return dc_change

    def dpc_change(self, source):
        # calculate the sum of dpci(source), i = 1,...,N
        src = addr2dec(source)
        dpc_change = 0
        for i in range(self.n):
            row = src % self.p[i]
            if row in self.row_change[i]:
                dpc_change += self.row_change[i][row][1]
            else:
                dpc_change += 0
        return dpc_change

    def anomaly_attribution_sip(self, sip_list):
        # source addresses anomaly attribution
        anomaly_attribution_sip = {}
        for se in sip_list:
            dc = self.cal_dc(se)
            dpc = self.cal_dpc(se)
            if self.row_change is None:
                if dc / dpc >= 5:
                    anomaly_type = 'horizontal scan'
                elif dpc / dc >= 5:
                    anomaly_type = 'vertical scan'
                else:
                    anomaly_type = 'undetermined abnormal'
            else:
                dc_change = self.dc_change(se)
                dpc_change = self.dpc_change(se)
                if dc / dpc > 5 or (dc_change * dpc_change != 0 and dc_change / dpc_change > 10):
                    anomaly_type = 'horizontal scan'
                elif dpc / dc > 5 or (dc_change * dpc_change != 0 and dpc_change / dc_change > 10):
                    anomaly_type = 'vertical scan'
                else:
                    anomaly_type = 'undetermined abnormal'

            anomaly_attribution_sip[se] = anomaly_type
        return anomaly_attribution_sip

    def anomaly_attribution_dip(self, dip_list):
        # destination addresses anomaly attribution
        anomaly_attribution_dip = {}
        for des in dip_list:
            dc = self.cal_dc(des)
            sc = self.cal_sc(des)
            if dc != 0 and sc / dc > 5:
                anomaly_type = 'victim'
            else:
                anomaly_type = 'service provider'
            anomaly_attribution_dip[des] = anomaly_type
        return anomaly_attribution_dip
