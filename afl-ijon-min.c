#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <time.h>

#include "afl-ijon-min.h"
#include "alloc-inl.h"

ijon_rule * ijon_rules=NULL;
ijon_rule * candidate_rules=NULL;//link list
linked_int * slots_focused=NULL;
char * old_max_filename=NULL;

ijon_input_info* new_ijon_input_info(char* max_dir, int i){
  ijon_input_info* self = malloc(sizeof(ijon_input_info));
  assert(asprintf(&self->filename,"%s/%d", max_dir, i)>0);
  self->slot_id = i;
	self->len = 0;
  return self;
}

ijon_min_state* new_ijon_min_state(char* max_dir) {
  ijon_min_state* self = malloc(sizeof(ijon_min_state));
  self->max_dir = max_dir;
  self->num_entries = 0;
	self->num_updates = 0;
  for(int i = 0; i< MAXMAP_SIZE; i++){
    self->max_map[i] = 0;
    self->infos[i]=new_ijon_input_info(max_dir, i);
  }
  return self;
}


u8 ijon_should_schedule(ijon_min_state* self){
  if(self->num_entries > 0){
    //return 1;
    return random()%100 > 20;
  }
  return 0;
}

ijon_input_info* ijon_get_input(ijon_min_state* self){
  if(self->max_map[14]>0){
	  //return self->infos[14];
  }
  uint32_t rnd = random()%self->num_entries;
  for(int i = 0; i<MAXMAP_SIZE; i++){
    if(self->max_map[i]>0){
      if(rnd==0){
        printf("schedule: %i %s\n",i, self->infos[i]->filename);
        return self->infos[i];
      }
      rnd-=1;
    }
  }
  return 0;
}
/*
void add_to_extras(char* oldfile, char* newfile, u32 *p_extras_cnt,struct extra_data** p_extras ){
	char *cmd=NULL;
	char *prefix="/home/yangke/Program/AFL/aflgo/bak/aflgo-good/tutorial/samples/apps/under-arrestment/liblouis/tools";
	assert(asprintf(&cmd,"radiff2 -O %s/%s %s/%s",prefix,oldfile,prefix,newfile));
	FILE * fp=popen(cmd,"r");
	if(!fp){
		assert(0);//Failed!
	}
	free(cmd);
	u8 result_buf[1024];
	while(fgets(result_buf, sizeof(result_buf), fp) != NULL){
		printf("radiff:%s\n",result_buf);
		u8 *p=result_buf;
		while((int)(p-result_buf)<1020 && *p!='>')p++;
		if((int)(p-result_buf)<1020){
			if(*(p+1)==' '){
				p+=2;
				u8 *start=p;
				int cnt=0;
				while(*p!=' '){
					p+=2;
					cnt++;
				}
				printf("%d\n",cnt);


				*p_extras = ck_realloc_block(*p_extras, (*p_extras_cnt + 1) *
											   sizeof(struct extra_data));
				u8* wptr = (*p_extras)[*p_extras_cnt].data = ck_alloc(cnt);
				(*p_extras)[*p_extras_cnt].len  = cnt;
				char* hexdigits = "0123456789abcdef";
				p=start;
				while(*p!=' '){
					*(wptr++) =
								((strchr(hexdigits, tolower(p[0])) - hexdigits) << 4) |
								(strchr(hexdigits, tolower(p[1])) - hexdigits);
					p+=2;
				}
				(*p_extras_cnt)++; printf("extra_cnt=%d",*p_extras_cnt);
			}
		}

	}
}*/

void generate_candidate_rules(char* oldfile, char* newfile){
	char *cmd=NULL;
	char *prefix=".";//current directory when running afl-fuzz
	assert(asprintf(&cmd,"radiff2 -O %s/%s %s/%s 2>&1",prefix,oldfile,prefix,newfile));
	FILE * fp=popen(cmd,"r");
	if(!fp){
		assert(0);//Failed!
	}
	free(cmd);
	u8 result_buf[2048];
	while(fgets(result_buf, sizeof(result_buf), fp) != NULL){
		if(!(result_buf[0]=='0' && result_buf[1]=='x')){
			if(result_buf[0]=='r'&&result_buf[6]=='2'){
				//"radiff2:"
				FATAL("%s",result_buf);
			}
			//FATAL("radiff:%s\n",result_buf);
			continue;
		}
		//OKF("radiff:%s\n",result_buf);

		ijon_rule *rule=(ijon_rule*)malloc(sizeof(ijon_rule));
		char *end;
		rule->s_offset=strtol(result_buf,&end,16);
		u8 *p=(u8*)(end+1);//skip a space
		rule->s_len=0;
		while(*p!=' '){
			p+=2;
			rule->s_len++;
		}
		p=end+1;//skip a space
		rule->s_chunk=(u8*)malloc(rule->s_len*sizeof(u8));
		u8 * wptr=rule->s_chunk;
		char* hexdigits = "0123456789abcdef";
		while(*p!=' '){
			*(wptr++) =
						((strchr(hexdigits, tolower(p[0])) - hexdigits) << 4) |
						(strchr(hexdigits, tolower(p[1])) - hexdigits);
			p+=2;
		}
		while((int)(p-result_buf)<2044 && *p!='>')p++; //skip '=>'

		p+=2;//skip a space
		u8 *start=p;
		rule->t_len=0;
		while(*p!=' '){
			p+=2;
			rule->t_len++;
		}
		//OKF("rule->t_len=%d %c",rule->t_len,*p);
		rule->t_chunk=(u8*)malloc(rule->t_len*sizeof(u8));

		wptr=rule->t_chunk;
		p=start;
		while(*p!=' '){
			*(wptr++) =
						((strchr(hexdigits, tolower(p[0])) - hexdigits) << 4) |
						(strchr(hexdigits, tolower(p[1])) - hexdigits);
			p+=2;
		}
		rule->t_offset=strtol(p+1,NULL,16);
		//OKF("%x %x %x => %x %x %x",rule->s_offset,rule->s_chunk[0],rule->s_len,rule->t_len,rule->t_chunk[0],rule->t_offset);
		//insert this rule to candidate
		rule->next=candidate_rules;
		candidate_rules=rule;
	}
}

int ijon_store_max_input(ijon_min_state* self, int i, uint8_t* data, size_t len,u32 parent_id){
	ijon_input_info* inf = self->infos[i];
	inf->len = len;
	int ret=0;
	
	char* filename = NULL;
	assert(asprintf(&filename, "%s/finding_%lu_%lu_v_%ld_par_%u", self->max_dir, self->num_updates, time(0), self->max_map[i],parent_id) > 0);
	self->num_updates+=1;
    int fd1 = open(filename, O_CREAT|O_TRUNC|O_WRONLY,0600);
    assert(write(fd1,data,len) == len);
    close(fd1);

    assert(inf->filename);
    FILE * tfp=fopen(inf->filename,"r");
    if(tfp){
    	fclose(tfp);
    	//add_to_extras(inf->filename,filename,p_extras_cnt,p_extras);
    	generate_candidate_rules(inf->filename,filename);
    	ret=1;
    }
    /* update old filename */
	if(old_max_filename){
		free(old_max_filename);
	}
	old_max_filename=filename;
	//free(filename);

	int fd0 = open(inf->filename, O_CREAT|O_TRUNC|O_WRONLY,0600);
	assert(write(fd0,data,len) == len);
	close(fd0);
	return ret;
}

void add_to_slots_focused(int x,int idx)
{
	linked_int *t=(linked_int*)malloc(sizeof(linked_int));
	t->v=x;
	t->idx=idx;
	t->next=slots_focused;
	slots_focused=t;
}

int ijon_update_max(ijon_min_state* self, shared_data_t* shared, uint8_t* data, size_t len, u32 parent_id){
	int should_min = (len>512) ;int ret=0;
  for(int i=0; i<MAXMAP_SIZE; i++){ 
    if(shared->afl_max[i] > self->max_map[i]){
      if(self->max_map[i]==0){ // found an input that triggers a new slot
        self->num_entries++;
      }
      self->max_map[i] = shared->afl_max[i];
      printf("updated maxmap %d: %lx (len: %ld) parent:%6u\n", i, self->max_map[i], len,parent_id);
      int rt=ijon_store_max_input(self, i, data, len,parent_id);
      if(rt && !ret){
    	  ret=1;
      }
      add_to_slots_focused(self->max_map[i],i);
    }else if(should_min && (shared->afl_max[i] == self->max_map[i] ) && ( len < self->infos[i]->len) ){
      printf("minimized maxmap %d: %lx (len: %ld) parent:%6u\n", i, self->max_map[i], len,parent_id);
			int rt=ijon_store_max_input(self,i,data,len,parent_id);
			add_to_slots_focused(self->max_map[i],i);
			if(rt && !ret){
			   ret=1;
		    }
			//add_to_slots_focused(self->max_map[i],i);
			//TODO: ret=1;
		}
  }

  return ret;
}
