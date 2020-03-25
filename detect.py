import pandas as pd
import os
import datetime


class Experiment:

    def __init__(self, file_path):
        self.file_path = file_path
        self.ssketch = None
        self.count = 0
        self.throughput = 0
        self.spreader_detect = []
        self.receiver_detect = []
        self.changer_detect = []
        self.src_list = []
        self.des_list = []
        self.spreader_real = None  # a list that records super spreaders addresses
        self.receiver_real = None  # a list that records  super receivers addresses
        self.changer_real = None  # a list that records  super changers addresses
        self.FPR_Spreader = None
        self.FPR_Changer = None
        self.FPR_Receiver = None
        self.FNR_Spreader = None
        self.FNR_Changer = None
        self.FNR_Receiver = None
        self.AREDC = 0
        self.AREDPC = 0
        self.ARESC = 0
        self.AAEDC = 0
        self.AAEDPC = 0
        self.AAESC = 0

    def step1(self):
        files = os.listdir(self.file_path)
        for file in files:
            self.count += 1
            print('No %d detection begins' % self.count)
            # Initialize
            self.ssketch.initialize()
            f = os.path.join(self.file_path, file)
            df = pd.read_csv(f, usecols=['Src IP', 'Dst IP', 'Dst Port'])
            table = df.drop_duplicates().reset_index(drop=True)
            print('Initialization finished. ')

            # Process data
            self.ssketch.process_data(table, 0, len(table))
            print('Data processing finished. ')
            through = len(table)/(endtime-starttime).total_seconds()
            self.throughput += through

            # ---------------calculate error-----------------

            # Statistical information of subtrace
            src_des = table.groupby('Src IP')['Dst IP'].nunique()
            src_port = table.groupby('Src IP')['Dst Port'].nunique()
            des_src = table.groupby('Dst IP')['Src IP'].nunique()

            num_src = len(src_des.index)  # the number of sources in a single subtrace
            num_des = len(des_src.index)  # the number of destinations in a single subtrace
            # num_dport = table['Dst Port'].nunique()  # the number of destination ports in a single subtrace
            self.src_list.extend(src_des.index)
            self.des_list.extend(des_src.index)

            dc_aresum = 0
            dpc_aresum = 0
            sc_aresum = 0
            dc_aaesum = 0
            dpc_aaesum = 0
            sc_aaesum = 0

            # Average Relative Error in cardinality (ARE)
            # Average Absolute Error in cardinality (AAE)

            # Calculate the ARE and AAE of dc(destination cardinality) in a single detection
            for item in src_des.index:
                real_dc = src_des[item]
                est_dc = self.ssketch.cal_dc(item)
                dc_aresum += float(abs(est_dc - real_dc)) / real_dc
                dc_aaesum += abs(est_dc - real_dc)
            ARE_dc = float(dc_aresum) / num_src
            AAE_dc = float(dc_aaesum) / num_src
            self.AREDC += ARE_dc
            self.AAEDC += AAE_dc

            # Calculate the ARE and AAE of dpc(destination port cardinality) in a single detection

            self.ssketch.sc_frequency = []
            for i in range(self.ssketch.n):
                sci = {}
                self.ssketch.sc_frequency.append(sci)
                for row in self.ssketch.sketch[i]:
                    for key in self.ssketch.sketch[i][row].keys():
                        self.ssketch.sc_frequency[i][key] = self.ssketch.sc_frequency[i].get(key, 0) + 1

            for item in src_port.index:
                real_dpc = src_port[item]
                est_dpc = self.ssketch.cal_dpc(item)
                dpc_aresum += float(abs(est_dpc - real_dpc)) / real_dpc
                dpc_aaesum += abs(est_dpc - real_dpc)
            ARE_dpc = float(dpc_aresum) / num_src
            AAE_dpc = float(dpc_aaesum) / num_src
            self.AREDPC += ARE_dpc
            self.AAEDPC += AAE_dpc

            # Calculate the ARE and AAE of sc(source cardinality) in a single detection
            for item in des_src.index:
                real_sc = des_src[item]
                est_sc = self.ssketch.cal_sc(item)
                sc_aresum += float(abs(est_sc - real_sc)) / real_sc
                sc_aaesum += abs(est_sc - real_sc)
            ARE_sc = float(sc_aresum) / num_des
            AAE_sc = float(sc_aaesum) / num_des
            self.ARESC += ARE_sc
            self.AAESC += AAE_sc

            print('ARE_dc : {}'.format(ARE_dc))
            print('ARE_dpc : {}'.format(ARE_dpc))
            print('ARE_sc : {}'.format(ARE_sc))
            print('AAE_dc : {}'.format(AAE_dc))
            print('AAE_dpc : {}'.format(AAE_dpc))
            print('AAE_sc : {}'.format(AAE_sc))
            print('No %d detection and analysis finished. \n' % self.count)

            # ---------------anomaly detection-----------------
            # Identify super rows, super changed rows and super columns
            abrow_list = self.ssketch.cal_abrow_list()
            abrow_list_spreader = abrow_list[0]
            abrow_list_changer = abrow_list[1]
            abcol_list_receiver = self.ssketch.cal_abcol_list()
            print('Abnormal rows/columns identification finished. ')

            # Reversibly reconstruct abnormal addresses
            sip_list_spreader = self.ssketch.recon_sip(abrow_list_spreader)
            if abrow_list_changer:
                sip_list_changer = self.ssketch.recon_sip(abrow_list_changer)
            else:
                sip_list_changer = []
            dip_list_receiver = self.ssketch.recon_dip(abcol_list_receiver)
            print('Reversible reconstruction finished. ')

            self.spreader_detect.extend(sip_list_spreader)
            self.changer_detect.extend(sip_list_changer)
            self.receiver_detect.extend(dip_list_receiver)

            # Anomaly attribute
            sip_list_abnormal = list(set(sip_list_spreader) | set(sip_list_changer))
            sip_attribution = self.ssketch.anomaly_attribution_sip(sip_list_abnormal)
            dip_attribution = self.ssketch.anomaly_attribution_dip(dip_list_receiver)
            print('Anomaly attribution finished. ')
            print('Abnormal source addresses attribution: ')
            print(sip_attribution)
            print('Abnormal destination addresses attribution: ')
            print(dip_attribution)

    def step2(self):
        # Evaluate performance
        sip = set(self.src_list)
        dip = set(self.des_list)
        num_src = len(sip)
        num_des = len(dip)
        # print('The total number of different source addresses in the trace : %d' % num_src)
        # print('The total number of different destination addresses in the trace : %d' % num_des)
        self.spreader_detect = set(self.spreader_detect)  # detected super spreader/receiver/changer in the trace
        self.changer_detect = set(self.changer_detect)
        self.receiver_detect = set(self.receiver_detect)

        print('Detected spreaders ：')
        print(self.spreader_detect)
        print('Detected changers ：')
        print(self.changer_detect)
        print('Detected receivers ：')
        print(self.receiver_detect)

        num_spreader_real = len(self.spreader_real)
        num_changer_real = len(self.changer_real)
        num_receiver_real = len(self.receiver_real)

        # FPR: False Positive Rate, the proportion of benign addresses that are mistakenly identified as super hosts
        # FNR: False Negative Rate, the proportion of super hosts that are not reported

        ab_sip_real = set(self.spreader_real) | set(self.changer_real)     # total number of real abnormal sources
        
        num_benign_sip = num_src - len(ab_sip_real)  # the number of benign addresses
        num_benign_dip = num_des - num_receiver_real

        mistaken_spreader = set(self.spreader_detect) - set(self.spreader_real)   # mistaken identified benign addresses
        mistaken_changer = set(self.changer_detect) - set(self.changer_real)
        mistaken_receiver = set(self.receiver_detect) - set(self.receiver_real)
        mistaken_num_spreader = len(mistaken_spreader)
        mistaken_num_changer = len(mistaken_changer)
        mistaken_num_receiver = len(mistaken_receiver)
        
        self.FPR_Spreader = float(mistaken_num_spreader) / num_benign_sip
        self.FPR_Changer = float(mistaken_num_changer) / num_benign_sip
        self.FPR_Receiver = float(mistaken_num_receiver) / num_benign_dip
        
        miss_spreader = set(self.spreader_real) - set(self.spreader_detect)  # super hosts not reported
        miss_changer = set(self.changer_real) - set(self.changer_detect)
        miss_receiver = set(self.receiver_real) - set(self.receiver_detect)
        miss_num_spreader = len(miss_spreader)
        miss_num_changer = len(miss_changer)
        miss_num_receiver = len(miss_receiver)
        
        if num_spreader_real == 0:
            self.FNR_Spreader = 0
        else:
            self.FNR_Spreader = float(miss_num_spreader) / num_spreader_real
        if num_changer_real == 0:
            self.FNR_Changer = 0
        else:
            self.FNR_Changer = float(miss_num_changer) / num_changer_real
        if num_receiver_real == 0:
            self.FNR_Receiver = 0
        else:
            self.FNR_Receiver = float(miss_num_receiver) / num_receiver_real

        print('FPR_Spreader : {:%}'.format(self.FPR_Spreader))
        print('FPR_Changer : {:%}'.format(self.FPR_Changer))
        print('FPR_Receiver : {:%}'.format(self.FPR_Receiver))
        print('FNR_Spreader : {:%}'.format(self.FNR_Spreader))
        print('FNR_Changer : {:%}'.format(self.FNR_Changer))
        print('FNR_Reveicer : {:%}'.format(self.FNR_Receiver))

        # calculate average
        self.AREDC = self.AREDC / self.count
        self.AREDPC = self.AREDPC / self.count
        self.ARESC = self.ARESC / self.count
        self.AAEDC = self.AAEDC / self.count
        self.AAEDPC = self.AAEDPC / self.count
        self.AAESC = self.AAESC / self.count
        self.throughput = self.throughput / self.count

        print('AREDC : {:.3f}'.format(self.AREDC))
        print('AREDPC : {:.3f}'.format(self.AREDPC))
        print('ARESC : {:.3f}'.format(self.ARESC))
        print('AAEDC : {:.3f}'.format(self.AAEDC))
        print('AAEDPC : {:.3f}'.format(self.AAEDPC))
        print('AAESC : {:.3f}'.format(self.AAESC))
        print('throughput : {:.3f}'.format(self.throughput))
