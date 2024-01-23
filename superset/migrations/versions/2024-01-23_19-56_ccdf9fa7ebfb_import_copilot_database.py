# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""import copilot database

Revision ID: ccdf9fa7ebfb
Revises: 59a1450b3c10
Create Date: 2024-01-23 19:56:52.005580

"""

# revision identifiers, used by Alembic.
revision = 'ccdf9fa7ebfb'
down_revision = '59a1450b3c10'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('interpret_material_qas')
    op.drop_table('model_usage')
    op.drop_table('summarization')
    op.drop_table('interpret_material_comments')
    op.drop_table('interpret_material_collections')
    op.drop_table('sensitive_words_dict')
    op.drop_table('embedding_data_item')
    op.drop_table('api_key_pool')
    op.drop_table('chat_summary')
    op.drop_table('model_dict')
    op.drop_table('chat_files')
    op.drop_table('interpret_material_contents')
    op.drop_table('character_functions')
    op.drop_table('functions')
    op.drop_table('event_track')
    op.drop_table('interpret_material')
    op.drop_table('embedding_chunks')
    op.drop_table('debug_questions')
    op.drop_table('interpret_material_user_read')
    op.drop_table('chat_debug_record')
    op.drop_table('user_character_keywords')
    op.drop_table('interpret_material_whitelist')
    op.drop_table('interpret_material_eventtrack')
    op.drop_table('embedding_data_source')
    op.drop_table('embedding_character_rel')
    op.drop_table('sys_config')
    op.drop_table('embedding_datas')
    op.drop_table('chat')
    op.drop_table('character')
    # ### end Alembic commands ###


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###

    op.create_table('character',
    sa.Column('id', sa.INTEGER(), server_default=sa.text("nextval('character_id_seq'::regclass)"), autoincrement=True, nullable=False),
    sa.Column('name', sa.VARCHAR(length=20), autoincrement=False, nullable=False),
    sa.Column('avatar', sa.TEXT(), autoincrement=False, nullable=True),
    sa.Column('description', sa.TEXT(), autoincrement=False, nullable=True),
    sa.Column('definition', sa.TEXT(), autoincrement=False, nullable=True),
    sa.Column('model', sa.TEXT(), server_default=sa.text("'gpt-3.5'::text"), autoincrement=False, nullable=True),
    sa.Column('user_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('is_public', sa.BOOLEAN(), server_default=sa.text('false'), autoincrement=False, nullable=True),
    sa.Column('is_default', sa.BOOLEAN(), server_default=sa.text('false'), autoincrement=False, nullable=True),
    sa.Column('is_system', sa.BOOLEAN(), server_default=sa.text('false'), autoincrement=False, nullable=True),
    sa.Column('welcome', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('preset_questions', postgresql.JSONB(astext_type=sa.Text()), autoincrement=False, nullable=True),
    sa.Column('sort', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('is_guest_access', sa.BOOLEAN(), server_default=sa.text('false'), autoincrement=False, nullable=True),
    sa.Column('recommend_enable', sa.BOOLEAN(), server_default=sa.text('false'), autoincrement=False, nullable=True),
    sa.Column('recommend_focus', sa.BOOLEAN(), server_default=sa.text('true'), autoincrement=False, nullable=True),
    sa.Column('temperature', sa.REAL(), server_default=sa.text('1'), autoincrement=False, nullable=True),
    sa.Column('frequency_penalty', sa.REAL(), server_default=sa.text('0'), autoincrement=False, nullable=True),
    sa.Column('is_audio_output', sa.BOOLEAN(), server_default=sa.text('false'), autoincrement=False, nullable=True),
    sa.Column('speech_model', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('speech_locale', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('speech_style', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('embedding_enable', sa.BOOLEAN(), server_default=sa.text('false'), autoincrement=False, nullable=True),
    sa.Column('max_history_token', sa.INTEGER(), server_default=sa.text('2048'), autoincrement=False, nullable=True),
    sa.Column('usage_count', sa.INTEGER(), server_default=sa.text('0'), autoincrement=False, nullable=True),
    sa.Column('is_embed', sa.BOOLEAN(), server_default=sa.text('false'), autoincrement=False, nullable=True),
    sa.Column('embed_domain', postgresql.JSONB(astext_type=sa.Text()), autoincrement=False, nullable=True),
    sa.Column('unique_id', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('is_image_output', sa.BOOLEAN(), server_default=sa.text('false'), autoincrement=False, nullable=True),
    sa.Column('image_model', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('input_type', sa.SMALLINT(), server_default=sa.text('1'), autoincrement=False, nullable=True),
    sa.Column('output_type', sa.SMALLINT(), server_default=sa.text('1'), autoincrement=False, nullable=True),
    sa.Column('greetings', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('industry', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('embedding_trigger_type', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('embedding_trigger_title', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('embed_security_tag_enable', sa.BOOLEAN(), autoincrement=False, nullable=True),
    sa.Column('embedding_hit_min_distance', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('embedding_hit_max_distance', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('embedding_inteligent_recommend', sa.BOOLEAN(), server_default=sa.text('false'), autoincrement=False, nullable=True),
    sa.Column('show_iframe_model_name', sa.BOOLEAN(), server_default=sa.text('true'), autoincrement=False, nullable=True),
    sa.Column('embedding_prompt', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('recommend_model', sa.INTEGER(), server_default=sa.text('1'), autoincrement=False, nullable=True),
    sa.Column('brand_params', postgresql.JSONB(astext_type=sa.Text()), autoincrement=False, nullable=True),
    sa.Column('quict_texts', postgresql.JSONB(astext_type=sa.Text()), autoincrement=False, nullable=True),
    sa.Column('support_workflow', sa.BOOLEAN(), server_default=sa.text('false'), autoincrement=False, nullable=True),
    sa.CheckConstraint("model = ANY (ARRAY['gpt-4'::text, 'dalle'::text, 'whisper-1'::text, 'azure-tts'::text, 'text-embedding-ada-002'::text, 'midjourney'::text, 'gpt-3.5'::text, 'gpt-vision'::text])", name='character_model_check'),
    sa.ForeignKeyConstraint(['user_id'], ['ab_user.id'], name='character_user_id_foreign', onupdate='CASCADE'),
    sa.PrimaryKeyConstraint('id', name='character_pkey'),
    postgresql_ignore_search_path=False
    )

    op.create_table('chat',
    sa.Column('id', sa.INTEGER(), server_default=sa.text("nextval('chat_id_seq'::regclass)"), autoincrement=True, nullable=False),
    sa.Column('user_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('character_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('messages', postgresql.JSONB(astext_type=sa.Text()), autoincrement=False, nullable=False),
    sa.Column('total_tokens', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True, precision=0), autoincrement=False, nullable=True),
    sa.Column('updated_at', postgresql.TIMESTAMP(timezone=True, precision=0), autoincrement=False, nullable=True),
    sa.Column('model', sa.TEXT(), server_default=sa.text("'gpt-3.5'::text"), autoincrement=False, nullable=True),
    sa.Column('is_debug', sa.BOOLEAN(), server_default=sa.text('false'), autoincrement=False, nullable=True),
    sa.CheckConstraint("model = ANY (ARRAY['gpt-4'::text, 'dalle'::text, 'whisper-1'::text, 'azure-tts'::text, 'text-embedding-ada-002'::text, 'midjourney'::text, 'gpt-3.5'::text, 'gpt-vision'::text])", name='chat_model_check'),
    sa.ForeignKeyConstraint(['character_id'], ['character.id'], name='chat_character_id_foreign', onupdate='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['ab_user.id'], name='chat_user_id_foreign', onupdate='CASCADE'),
    sa.PrimaryKeyConstraint('id', name='chat_pkey'),
    postgresql_ignore_search_path=False
    )
 
 
    op.create_table('embedding_datas',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('title', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('user_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True, precision=0), autoincrement=False, nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['ab_user.id'], name='embedding_datas_user_id_foreign', onupdate='CASCADE'),
    sa.PrimaryKeyConstraint('id', name='embedding_datas_pkey')
    )
    op.create_table('sys_config',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('config_key', sa.VARCHAR(length=255), autoincrement=False, nullable=False),
    sa.Column('config_value', sa.VARCHAR(length=255), autoincrement=False, nullable=False),
    sa.PrimaryKeyConstraint('id', name='sys_config_pkey')
    )
    op.create_table('embedding_character_rel',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('character_id', sa.VARCHAR(length=11), autoincrement=False, nullable=False),
    sa.Column('data_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.PrimaryKeyConstraint('id', name='embedding_character_rel_pkey')
    )
    op.create_table('embedding_data_source',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('data_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('data_item_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('source_type', sa.SMALLINT(), autoincrement=False, nullable=False),
    sa.Column('file_path', sa.VARCHAR(length=512), autoincrement=False, nullable=True),
    sa.Column('file_name', sa.VARCHAR(length=512), autoincrement=False, nullable=True),
    sa.Column('file_size', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('create_user_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('create_at', postgresql.TIMESTAMP(timezone=True, precision=0), autoincrement=False, nullable=True),
    sa.Column('source_desc', sa.TEXT(), autoincrement=False, nullable=True),
    sa.ForeignKeyConstraint(['create_user_id'], ['ab_user.id'], name='embedding_data_source_create_user_id_foreign', onupdate='CASCADE'),
    sa.PrimaryKeyConstraint('id', name='embedding_data_source_pkey')
    )

    op.create_table('functions',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('name', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('title', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('description', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('parameters', sa.VARCHAR(length=255), server_default=sa.text("'{}'::character varying"), autoincrement=False, nullable=False),
    sa.Column('enable', sa.BOOLEAN(), server_default=sa.text('true'), autoincrement=False, nullable=False),
    sa.Column('prompt', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('model', sa.TEXT(), server_default=sa.text("'gpt-3.5'::text"), autoincrement=False, nullable=True),
    sa.Column('remark', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('type', sa.SMALLINT(), server_default=sa.text('1'), autoincrement=False, nullable=False),
    sa.Column('file_multiple', sa.BOOLEAN(), server_default=sa.text('false'), autoincrement=False, nullable=False),
    sa.Column('input_file', sa.BOOLEAN(), server_default=sa.text('false'), autoincrement=False, nullable=False),
    sa.Column('file_types', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), autoincrement=False, nullable=False),
    sa.Column('result_use_prompt', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.CheckConstraint("model = ANY (ARRAY['gpt-4'::text, 'dalle'::text, 'whisper-1'::text, 'azure-tts'::text, 'text-embedding-ada-002'::text, 'midjourney'::text, 'gpt-3.5'::text, 'gpt-vision'::text])", name='functions_model_check'),
    sa.PrimaryKeyConstraint('id', name='functions_pkey')
    )

    op.create_table('character_functions',
    sa.Column('character_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('functions_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.ForeignKeyConstraint(['character_id'], ['character.id'], name='character_functions_character_id_foreign', onupdate='CASCADE', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['functions_id'], ['functions.id'], name='character_functions_functions_id_foreign', onupdate='CASCADE', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('character_id', 'functions_id', name='character_functions_pkey')
    )
    op.create_table('interpret_material_eventtrack',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('event', sa.TEXT(), autoincrement=False, nullable=False),
    sa.Column('value', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('user_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('extra', postgresql.JSONB(astext_type=sa.Text()), autoincrement=False, nullable=True),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True, precision=0), autoincrement=False, nullable=True),
    sa.Column('entity_id', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.CheckConstraint("event = ANY (ARRAY['comment_upvote'::text, 'question_upvote'::text, 'open_question'::text, 'open_material'::text, 'query_material'::text, 'chat'::text, 'invoke_knowledge'::text, 'invoke_qa'::text, 'global_chat'::text, 'invoke_plugin'::text])", name='interpret_material_eventtrack_event_check'),
    sa.ForeignKeyConstraint(['user_id'], ['ab_user.id'], name='interpret_material_eventtrack_user_id_foreign', onupdate='CASCADE'),
    sa.PrimaryKeyConstraint('id', name='interpret_material_eventtrack_pkey')
    )
    op.create_table('interpret_material_whitelist',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('user_ids', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('title', sa.VARCHAR(length=255), autoincrement=False, nullable=False),
    sa.PrimaryKeyConstraint('id', name='interpret_material_whitelist_pkey')
    )
    op.create_table('user_character_keywords',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('user_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('character_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('keyword', sa.VARCHAR(length=255), autoincrement=False, nullable=False),
    sa.Column('hit_count', sa.INTEGER(), server_default=sa.text('0'), autoincrement=False, nullable=True),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True, precision=0), autoincrement=False, nullable=False),
    sa.Column('updated_at', postgresql.TIMESTAMP(timezone=True, precision=0), autoincrement=False, nullable=False),
    sa.ForeignKeyConstraint(['character_id'], ['character.id'], name='user_character_keywords_character_id_foreign', onupdate='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['ab_user.id'], name='user_character_keywords_user_id_foreign', onupdate='CASCADE'),
    sa.PrimaryKeyConstraint('id', name='user_character_keywords_pkey')
    )
    op.create_table('chat_debug_record',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('user_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('chat_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('message_index_start', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('message_index_end', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('model', sa.TEXT(), autoincrement=False, nullable=True),
    sa.Column('user_input', sa.TEXT(), autoincrement=False, nullable=True),
    sa.Column('knowledges', postgresql.JSONB(astext_type=sa.Text()), autoincrement=False, nullable=True),
    sa.Column('knowledge_result', postgresql.JSONB(astext_type=sa.Text()), autoincrement=False, nullable=True),
    sa.Column('embedding_prompt', sa.TEXT(), autoincrement=False, nullable=True),
    sa.Column('output_content', postgresql.JSONB(astext_type=sa.Text()), autoincrement=False, nullable=True),
    sa.Column('output_type', sa.SMALLINT(), autoincrement=False, nullable=True),
    sa.Column('boot_question_prompt', sa.TEXT(), autoincrement=False, nullable=True),
    sa.Column('boot_questions', postgresql.JSONB(astext_type=sa.Text()), autoincrement=False, nullable=True),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True, precision=0), autoincrement=False, nullable=True),
    sa.Column('function_detail', postgresql.JSONB(astext_type=sa.Text()), autoincrement=False, nullable=True),
    sa.ForeignKeyConstraint(['chat_id'], ['chat.id'], name='chat_debug_record_chat_id_foreign', onupdate='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['ab_user.id'], name='chat_debug_record_user_id_foreign', onupdate='CASCADE'),
    sa.PrimaryKeyConstraint('id', name='chat_debug_record_pkey')
    )
    op.create_table('interpret_material_user_read',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('material_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('user_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('reading_status', sa.SMALLINT(), server_default=sa.text('1'), autoincrement=False, nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['ab_user.id'], name='interpret_material_user_read_user_id_foreign', onupdate='CASCADE'),
    sa.PrimaryKeyConstraint('id', name='interpret_material_user_read_pkey')
    )
    op.create_table('debug_questions',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('user_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('question', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True, precision=0), autoincrement=False, nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['ab_user.id'], name='debug_questions_user_id_foreign', onupdate='CASCADE'),
    sa.PrimaryKeyConstraint('id', name='debug_questions_pkey')
    )
    op.create_table('embedding_chunks',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('data_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('data_item_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('data_index', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('chunk_content', sa.TEXT(), autoincrement=False, nullable=True),
    sa.Column('chunk_meta', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), autoincrement=False, nullable=False),
    sa.Column('chunk_status', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('number_of_hits', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True, precision=0), autoincrement=False, nullable=True),
    sa.Column('embedding_trigger_type', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.PrimaryKeyConstraint('id', name='embedding_chunks_pkey')
    )

    op.create_table('interpret_material',
    sa.Column('id', sa.INTEGER(), server_default=sa.text("nextval('interpret_material_id_seq'::regclass)"), autoincrement=True, nullable=False),
    sa.Column('character_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('cover_url', sa.VARCHAR(length=255), autoincrement=False, nullable=False),
    sa.Column('author', sa.VARCHAR(length=255), autoincrement=False, nullable=False),
    sa.Column('title', sa.VARCHAR(length=255), autoincrement=False, nullable=False),
    sa.Column('desc', sa.TEXT(), autoincrement=False, nullable=False),
    sa.Column('top_color', sa.VARCHAR(length=255), autoincrement=False, nullable=False),
    sa.Column('open_scope', sa.SMALLINT(), autoincrement=False, nullable=False),
    sa.Column('whitelist_id', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('ctime', postgresql.TIMESTAMP(timezone=True, precision=0), autoincrement=False, nullable=True),
    sa.Column('open_count', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('read_count', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('is_del', sa.SMALLINT(), autoincrement=False, nullable=True),
    sa.Column('user_read_status', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.ForeignKeyConstraint(['character_id'], ['character.id'], name='interpret_material_character_id_foreign', onupdate='CASCADE'),
    sa.PrimaryKeyConstraint('id', name='interpret_material_pkey'),
    postgresql_ignore_search_path=False
    )
    op.create_table('event_track',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('event', sa.TEXT(), autoincrement=False, nullable=False),
    sa.Column('value', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('user_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('extra', postgresql.JSONB(astext_type=sa.Text()), autoincrement=False, nullable=True),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True, precision=0), autoincrement=False, nullable=True),
    sa.Column('character_id', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.CheckConstraint("event = ANY (ARRAY['login'::text, 'register'::text, 'open_register'::text, 'mj_generated'::text, 'mj_share'::text, 'mj_share_enter'::text, 'mj_open'::text, 'mj_generate'::text, 'open_embed_chat'::text, 'embed_chating'::text])", name='event_track_event_check'),
    sa.ForeignKeyConstraint(['user_id'], ['ab_user.id'], name='event_track_user_id_foreign', onupdate='CASCADE'),
    sa.PrimaryKeyConstraint('id', name='event_track_pkey')
    )

    op.create_table('interpret_material_contents',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('material_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('file_url', sa.VARCHAR(length=255), autoincrement=False, nullable=False),
    sa.Column('content', sa.TEXT(), autoincrement=False, nullable=False),
    sa.Column('file_type', sa.SMALLINT(), autoincrement=False, nullable=True),
    sa.Column('is_del', sa.SMALLINT(), autoincrement=False, nullable=True),
    sa.Column('sort', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.PrimaryKeyConstraint('id', name='interpret_material_contents_pkey')
    )
    op.create_table('chat_files',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('chat_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('batch_no', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('file_unique_name', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('file_name', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('file_type', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('file_path', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('file_size', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('vision_result', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.ForeignKeyConstraint(['chat_id'], ['chat.id'], name='chat_files_chat_id_foreign', onupdate='CASCADE'),
    sa.PrimaryKeyConstraint('id', name='chat_files_pkey')
    )
    op.create_table('model_dict',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('model_name', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('model_key', sa.TEXT(), server_default=sa.text("'gpt-3.5'::text"), autoincrement=False, nullable=False),
    sa.Column('key_branch', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.CheckConstraint("model_key = ANY (ARRAY['gpt-4'::text, 'dalle'::text, 'whisper-1'::text, 'azure-tts'::text, 'text-embedding-ada-002'::text, 'midjourney'::text, 'gpt-3.5'::text, 'gpt-vision'::text])", name='model_dict_model_key_check'),
    sa.PrimaryKeyConstraint('id', name='model_dict_pkey')
    )
    op.create_table('chat_summary',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('chat_id', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('summary', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True, precision=0), autoincrement=False, nullable=True),
    sa.PrimaryKeyConstraint('id', name='chat_summary_pkey')
    )
    op.create_table('api_key_pool',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('api_key', sa.VARCHAR(length=255), autoincrement=False, nullable=False),
    sa.Column('latest_support_version', sa.VARCHAR(length=10), autoincrement=False, nullable=False),
    sa.Column('available', sa.BOOLEAN(), server_default=sa.text('true'), autoincrement=False, nullable=True),
    sa.Column('org_id', sa.VARCHAR(length=255), autoincrement=False, nullable=False),
    sa.Column('desc', sa.VARCHAR(length=255), autoincrement=False, nullable=False),
    sa.Column('hard_limit_usd', postgresql.DOUBLE_PRECISION(precision=53), autoincrement=False, nullable=False),
    sa.Column('weight', sa.REAL(), autoincrement=False, nullable=False),
    sa.Column('type', sa.TEXT(), server_default=sa.text("'openai'::text"), autoincrement=False, nullable=True),
    sa.Column('update_time', postgresql.TIMESTAMP(timezone=True, precision=0), autoincrement=False, nullable=False),
    sa.Column('base_path', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('prices', postgresql.JSONB(astext_type=sa.Text()), autoincrement=False, nullable=False),
    sa.CheckConstraint("type = ANY (ARRAY['openai'::text, 'openai-sb'::text])", name='api_key_pool_type_check'),
    sa.PrimaryKeyConstraint('id', name='api_key_pool_pkey')
    )
    op.create_table('embedding_data_item',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('title', sa.VARCHAR(length=255), autoincrement=False, nullable=False),
    sa.Column('data_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('data_type', sa.SMALLINT(), autoincrement=False, nullable=False),
    sa.Column('index_file_path', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('retrain_status', sa.SMALLINT(), autoincrement=False, nullable=False),
    sa.Column('is_enable', sa.BOOLEAN(), server_default=sa.text('true'), autoincrement=False, nullable=True),
    sa.Column('chunk_size', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('split_type', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('split_separator', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('number_of_hits', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True, precision=0), autoincrement=False, nullable=True),
    sa.Column('updated_at', postgresql.TIMESTAMP(timezone=True, precision=0), autoincrement=False, nullable=True),
    sa.PrimaryKeyConstraint('id', name='embedding_data_item_pkey')
    )
    op.create_table('sensitive_words_dict',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('keyword', sa.VARCHAR(length=255), autoincrement=False, nullable=False),
    sa.PrimaryKeyConstraint('id', name='sensitive_words_dict_pkey')
    )
    op.create_table('interpret_material_collections',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('material_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('user_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('question', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('answer', postgresql.JSONB(astext_type=sa.Text()), autoincrement=False, nullable=True),
    sa.Column('is_del', sa.SMALLINT(), autoincrement=False, nullable=True),
    sa.Column('join_qa', sa.BOOLEAN(), server_default=sa.text('false'), autoincrement=False, nullable=False),
    sa.ForeignKeyConstraint(['material_id'], ['interpret_material.id'], name='interpret_material_collections_material_id_foreign', onupdate='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['ab_user.id'], name='interpret_material_collections_user_id_foreign', onupdate='CASCADE'),
    sa.PrimaryKeyConstraint('id', name='interpret_material_collections_pkey')
    )
    op.create_table('interpret_material_comments',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('material_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('qas_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('user_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('parent_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('root_code', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('topic_id', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('topic_type', sa.SMALLINT(), autoincrement=False, nullable=True),
    sa.Column('content', sa.TEXT(), autoincrement=False, nullable=False),
    sa.Column('is_del', sa.SMALLINT(), autoincrement=False, nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['ab_user.id'], name='interpret_material_comments_user_id_foreign', onupdate='CASCADE'),
    sa.PrimaryKeyConstraint('id', name='interpret_material_comments_pkey')
    )
    op.create_table('summarization',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('user_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('summary_prompt', sa.TEXT(), autoincrement=False, nullable=True),
    sa.Column('file_path', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('status', sa.SMALLINT(), autoincrement=False, nullable=True),
    sa.Column('content', sa.TEXT(), autoincrement=False, nullable=True),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True, precision=0), autoincrement=False, nullable=True),
    sa.Column('finish_time', postgresql.TIMESTAMP(timezone=True, precision=0), autoincrement=False, nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['ab_user.id'], name='summarization_user_id_foreign', onupdate='CASCADE'),
    sa.PrimaryKeyConstraint('id', name='summarization_pkey')
    )

    op.create_table('model_usage',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('model', sa.VARCHAR(length=255), server_default=sa.text("'gpt-3.5'::character varying"), autoincrement=False, nullable=True),
    sa.Column('tokens', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('messages', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('month', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('day', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('price', sa.NUMERIC(precision=10, scale=0), autoincrement=False, nullable=True),
    sa.Column('split_price', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.PrimaryKeyConstraint('id', name='model_usage_pkey')
    )
    op.create_table('interpret_material_qas',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('material_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('material_content_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('chunk_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('chunk_content', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('open_count', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('comment_count', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('upvote_count', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('is_del', sa.SMALLINT(), autoincrement=False, nullable=True),
    sa.Column('is_important', sa.SMALLINT(), autoincrement=False, nullable=True),
    sa.PrimaryKeyConstraint('id', name='interpret_material_qas_pkey')
    )
    # ### end Alembic commands ###
